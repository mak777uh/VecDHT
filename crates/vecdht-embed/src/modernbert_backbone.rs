//! ModernBERT backbone для granite-97m-r2, вендоренный из candle-transformers 0.10.2.
//!
//! Причина вендоринга — не «своя модель», а конкретное расхождение, пойманное гейтом (v):
//! `candle_transformers::models::modernbert` жёстко применяет GELU в GeGLU-MLP и игнорирует
//! `hidden_activation` из `config.json`. У `ibm-granite/granite-embedding-97m-multilingual-r2`
//! этот параметр равен `silu`; HF-референс считает SiLU. На одном и том же тексте косинус
//! GELU-варианта против HF составлял 0.860040 при пороге 0.999, то есть это была бы не
//! «мелкая численная разница», а другой энкодер под тем же именем.
//!
//! Оригинал: <https://github.com/huggingface/candle>, `candle-transformers/src/models/modernbert.rs`,
//! лицензия MIT OR Apache-2.0, copyright Hugging Face / candle contributors. Здесь оставлен только
//! backbone (без decoder/MLM/classification) и активация MLP вынесена в [`Activation`]. Формулы
//! attention, RoPE, масок и слоёв не менялись: любая правка в них должна ловиться тем же гейтом (v).

use candle_core::{DType, Device, Result, Tensor, D};
use candle_nn::{
    embedding, layer_norm_no_bias, linear_no_bias, ops::softmax, Embedding, LayerNorm, Linear,
    Module, VarBuilder,
};
use candle_transformers::models::modernbert::Config;
use serde::Deserialize;
use std::sync::Arc;

/// Активация GeGLU-MLP. Значение берётся из `hidden_activation` в `config.json` (§6.2 шаг 4).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Activation {
    /// Точный GELU (`torch.nn.GELU()`), который использует upstream candle.
    Gelu,
    /// SiLU, объявленный в config.json granite-97m-r2.
    Silu,
}

impl Activation {
    /// Разобрать имя из `config.json`. Неизвестное имя — ошибка, а не тихий GELU: иначе
    /// расхождение с HF снова стало бы невидимым.
    pub fn from_name(name: &str) -> std::result::Result<Self, String> {
        match name {
            "gelu" => Ok(Self::Gelu),
            "silu" => Ok(Self::Silu),
            other => Err(format!(
                "hidden_activation = {other:?}: поддерживаются только \"gelu\" и \"silu\""
            )),
        }
    }

    fn apply(self, xs: &Tensor) -> Result<Tensor> {
        match self {
            Self::Gelu => xs.gelu_erf(),
            Self::Silu => xs.silu(),
        }
    }
}

#[derive(Debug, Clone, Deserialize)]
struct ActivationField {
    #[serde(default = "default_activation")]
    hidden_activation: String,
}

fn default_activation() -> String {
    // У ModernBERT по умолчанию gelu; если поле отсутствует, ведём себя как upstream candle.
    "gelu".to_string()
}

/// Прочитать активацию из тех же байтов `config.json`, которые уже разобраны в [`Config`]:
/// candle-структура этого поля не содержит и молча его теряет.
pub fn activation_from_config_json(text: &str) -> std::result::Result<Activation, String> {
    let field: ActivationField = serde_json::from_str(text)
        .map_err(|e| format!("hidden_activation: {e}"))?;
    Activation::from_name(&field.hidden_activation)
}

#[derive(Debug, Clone)]
struct RotaryEmbedding {
    sin: Tensor,
    cos: Tensor,
}

impl RotaryEmbedding {
    fn new(dtype: DType, config: &Config, rope_theta: f64, dev: &Device) -> Result<Self> {
        let dim = config.hidden_size / config.num_attention_heads;
        let inv_freq: Vec<_> = (0..dim)
            .step_by(2)
            .map(|i| 1f32 / rope_theta.powf(i as f64 / dim as f64) as f32)
            .collect();
        let inv_freq_len = inv_freq.len();
        let inv_freq = Tensor::from_vec(inv_freq, (1, inv_freq_len), dev)?.to_dtype(dtype)?;
        let max_seq_len = config.max_position_embeddings;
        let t = Tensor::arange(0u32, max_seq_len as u32, dev)?
            .to_dtype(dtype)?
            .reshape((max_seq_len, 1))?;
        let freqs = t.matmul(&inv_freq)?;
        Ok(Self {
            sin: freqs.sin()?,
            cos: freqs.cos()?,
        })
    }

    fn apply_rotary_emb_qkv(&self, q: &Tensor, k: &Tensor) -> Result<(Tensor, Tensor)> {
        let q_embed = candle_nn::rotary_emb::rope(&q.contiguous()?, &self.cos, &self.sin)?;
        let k_embed = candle_nn::rotary_emb::rope(&k.contiguous()?, &self.cos, &self.sin)?;
        Ok((q_embed, k_embed))
    }
}

#[derive(Clone)]
struct Attention {
    qkv: Linear,
    proj: Linear,
    num_attention_heads: usize,
    attention_head_size: usize,
    rotary_emb: Arc<RotaryEmbedding>,
}

impl Attention {
    fn load(vb: VarBuilder, config: &Config, rotary_emb: Arc<RotaryEmbedding>) -> Result<Self> {
        let num_attention_heads = config.num_attention_heads;
        let attention_head_size = config.hidden_size / config.num_attention_heads;

        let qkv = linear_no_bias(config.hidden_size, config.hidden_size * 3, vb.pp("Wqkv"))?;
        let proj = linear_no_bias(config.hidden_size, config.hidden_size, vb.pp("Wo"))?;

        Ok(Self {
            qkv,
            proj,
            num_attention_heads,
            attention_head_size,
            rotary_emb,
        })
    }

    fn forward(&self, hidden_states: &Tensor, attention_mask: &Tensor) -> Result<Tensor> {
        let xs = hidden_states.clone();
        let (b, seq_len, d) = xs.dims3()?;
        let qkv = xs
            .apply(&self.qkv)?
            .reshape((
                b,
                seq_len,
                3,
                self.num_attention_heads,
                self.attention_head_size,
            ))?
            .permute((2, 0, 3, 1, 4))?;

        let q = qkv.get(0)?;
        let k = qkv.get(1)?;
        let v = qkv.get(2)?;

        let (q, k) = self.rotary_emb.apply_rotary_emb_qkv(&q, &k)?;

        let scale = (self.attention_head_size as f64).powf(-0.5);
        let q = (q * scale)?;

        let att = q.matmul(&k.transpose(D::Minus2, D::Minus1)?)?;
        let att = att.broadcast_add(attention_mask)?;
        let att = softmax(&att, D::Minus1)?;

        let xs = att.matmul(&v)?;
        let xs = xs.transpose(1, 2)?.reshape((b, seq_len, d))?;
        let xs = xs.apply(&self.proj)?;
        let xs = xs.reshape((b, seq_len, d))?;
        Ok(xs)
    }
}

#[derive(Clone)]
struct Mlp {
    wi: Linear,
    wo: Linear,
    activation: Activation,
}

impl Mlp {
    fn load(vb: VarBuilder, config: &Config, activation: Activation) -> Result<Self> {
        let wi = linear_no_bias(
            config.hidden_size,
            config.intermediate_size * 2,
            vb.pp("Wi"),
        )?;
        let wo = linear_no_bias(config.intermediate_size, config.hidden_size, vb.pp("Wo"))?;
        Ok(Self { wi, wo, activation })
    }
}

impl Module for Mlp {
    fn forward(&self, xs: &Tensor) -> Result<Tensor> {
        let xs = xs.apply(&self.wi)?;
        let xs = xs.chunk(2, D::Minus1)?;
        // В отличие от upstream candle: не gelu_erf(), а активация из config.json.
        let xs = (self.activation.apply(&xs[0])? * &xs[1])?.apply(&self.wo)?;
        Ok(xs)
    }
}

#[derive(Clone)]
struct Layer {
    attn: Attention,
    mlp: Mlp,
    attn_norm: Option<LayerNorm>,
    mlp_norm: LayerNorm,
    uses_local_attention: bool,
}

impl Layer {
    fn load(
        vb: VarBuilder,
        config: &Config,
        rotary_emb: Arc<RotaryEmbedding>,
        uses_local_attention: bool,
        activation: Activation,
    ) -> Result<Self> {
        let attn = Attention::load(vb.pp("attn"), config, rotary_emb)?;
        let mlp = Mlp::load(vb.pp("mlp"), config, activation)?;
        // У первого слоя HF использует nn.Identity(); в checkpoint тензора attn_norm нет.
        let attn_norm = layer_norm_no_bias(
            config.hidden_size,
            config.layer_norm_eps,
            vb.pp("attn_norm"),
        )
        .ok();
        let mlp_norm =
            layer_norm_no_bias(config.hidden_size, config.layer_norm_eps, vb.pp("mlp_norm"))?;
        Ok(Self {
            attn,
            mlp,
            attn_norm,
            mlp_norm,
            uses_local_attention,
        })
    }

    fn forward(
        &self,
        xs: &Tensor,
        global_attention_mask: &Tensor,
        local_attention_mask: &Tensor,
    ) -> Result<Tensor> {
        let residual = xs.clone();
        let mut xs = xs.clone();
        if let Some(norm) = &self.attn_norm {
            xs = xs.apply(norm)?;
        }

        let attention_mask = if self.uses_local_attention {
            &global_attention_mask.broadcast_add(local_attention_mask)?
        } else {
            global_attention_mask
        };
        let xs = self.attn.forward(&xs, attention_mask)?;
        let xs = (xs + residual)?;
        let mlp_out = xs.apply(&self.mlp_norm)?.apply(&self.mlp)?;
        let xs = (xs + mlp_out)?;
        Ok(xs)
    }
}

// Global attention mask calculated from padded token inputs
fn prepare_4d_attention_mask(
    mask: &Tensor,
    dtype: DType,
    tgt_len: Option<usize>,
) -> Result<Tensor> {
    let bsz = mask.dim(0)?;
    let src_len = mask.dim(1)?;
    let tgt_len = tgt_len.unwrap_or(src_len);

    let expanded_mask = mask
        .unsqueeze(1)?
        .unsqueeze(2)?
        .expand((bsz, 1, tgt_len, src_len))?
        .to_dtype(dtype)?;

    let inverted_mask = (1.0 - expanded_mask)?;

    (inverted_mask * f32::MIN as f64)?.to_dtype(dtype)
}

// Attention mask caused by the sliding window
fn get_local_attention_mask(
    seq_len: usize,
    max_distance: usize,
    device: &Device,
) -> Result<Tensor> {
    let mask: Vec<_> = (0..seq_len)
        .flat_map(|i| {
            (0..seq_len).map(move |j| {
                if (j as i32 - i as i32).abs() > max_distance as i32 {
                    f32::NEG_INFINITY
                } else {
                    0.
                }
            })
        })
        .collect();
    Tensor::from_slice(&mask, (seq_len, seq_len), device)
}

/// Bi-encoder backbone: эмбеддинги + 12 слоёв + final_norm. Возвращает скрытые состояния
/// `(1, seq, hidden_size)`; pooling делает вызывающий код (§6.2 шаг 5).
pub struct Backbone {
    word_embeddings: Embedding,
    norm: LayerNorm,
    layers: Vec<Layer>,
    final_norm: LayerNorm,
    local_attention_size: usize,
}

impl Backbone {
    /// Загрузить веса. Ожидает префикс `model.` (как upstream candle); `candle_backend`
    /// нормализует его для checkpoint'ов `ModernBertModel`, где префикса нет.
    pub fn load(
        vb: VarBuilder,
        config: &Config,
        activation: Activation,
    ) -> Result<Self> {
        let word_embeddings = embedding(
            config.vocab_size,
            config.hidden_size,
            vb.pp("model.embeddings.tok_embeddings"),
        )?;
        let norm = layer_norm_no_bias(
            config.hidden_size,
            config.layer_norm_eps,
            vb.pp("model.embeddings.norm"),
        )?;
        let global_rotary_emb = Arc::new(RotaryEmbedding::new(
            vb.dtype(),
            config,
            config.global_rope_theta,
            vb.device(),
        )?);
        let local_rotary_emb = Arc::new(RotaryEmbedding::new(
            vb.dtype(),
            config,
            config.local_rope_theta,
            vb.device(),
        )?);

        let mut layers = Vec::with_capacity(config.num_hidden_layers);
        for layer_id in 0..config.num_hidden_layers {
            let uses_local_attention = layer_id % config.global_attn_every_n_layers != 0;
            layers.push(Layer::load(
                vb.pp(format!("model.layers.{layer_id}")),
                config,
                if uses_local_attention {
                    local_rotary_emb.clone()
                } else {
                    global_rotary_emb.clone()
                },
                uses_local_attention,
                activation,
            )?);
        }

        let final_norm = layer_norm_no_bias(
            config.hidden_size,
            config.layer_norm_eps,
            vb.pp("model.final_norm"),
        )?;

        Ok(Self {
            word_embeddings,
            norm,
            layers,
            final_norm,
            local_attention_size: config.local_attention,
        })
    }

    pub fn forward(&self, xs: &Tensor, mask: &Tensor) -> Result<Tensor> {
        let seq_len = xs.shape().dims()[1];
        let global_attention_mask =
            prepare_4d_attention_mask(mask, DType::F32, None)?.to_device(xs.device())?;
        let local_attention_mask =
            get_local_attention_mask(seq_len, self.local_attention_size / 2, xs.device())?;
        let mut xs = xs.apply(&self.word_embeddings)?.apply(&self.norm)?;
        for layer in self.layers.iter() {
            xs = layer.forward(&xs, &global_attention_mask, &local_attention_mask)?;
        }
        let xs = xs.apply(&self.final_norm)?;
        Ok(xs)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn activation_is_read_from_config_and_unknown_is_an_error() {
        assert_eq!(
            activation_from_config_json(r#"{"hidden_activation":"silu"}"#).unwrap(),
            Activation::Silu
        );
        assert_eq!(
            activation_from_config_json(r#"{"hidden_activation":"gelu"}"#).unwrap(),
            Activation::Gelu
        );
        assert_eq!(
            activation_from_config_json("{}").unwrap(),
            Activation::Gelu,
            "поле отсутствует — поведение upstream candle"
        );
        assert!(activation_from_config_json(r#"{"hidden_activation":"relu"}"#).is_err());
    }

    #[test]
    fn silu_and_gelu_are_not_interchangeable() {
        let xs = Tensor::from_slice(&[-1.5f32, 0.0, 1.5], 3, &Device::Cpu).unwrap();
        let silu = Activation::Silu.apply(&xs).unwrap().to_vec1::<f32>().unwrap();
        let gelu = Activation::Gelu.apply(&xs).unwrap().to_vec1::<f32>().unwrap();
        assert!((silu[2] - 1.5 / (1.0 + (-1.5f32).exp())).abs() < 1e-6);
        assert!((silu[2] - gelu[2]).abs() > 1e-3, "активации обязаны различаться");
    }
}
