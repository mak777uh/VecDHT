//! Fixed little-endian кодек VecDHT v8 (спека §5.1, §5.2).
//!
//! Это **единственная** реализация кодирования в проекте: Python SDK вызывает её через
//! PyO3 и ничего не кодирует сам (дефект №10 в v7.5 — межъязыковой канонический энкодер).
//!
//! Правила (консенсусные, проверяются golden-векторами):
//! 1. все целые — little-endian, без padding между полями фиксированной части;
//! 2. массивы фиксированной длины — без length-prefix;
//! 3. variable-length — `[u16 len][bytes]`;
//! 4. хвост — TLV: `[u16 tag][u16 len][value]`, теги возрастающие, неизвестный тег
//!    игнорируется, дубликат тега — ошибка декода;
//! 5. enums — `u8`, неизвестное значение — `DecodeError::BadEnum`;
//! 6. никаких float в подписываемых полях.

use thiserror::Error;

/// Длина квантованного вектора в байтах. Это факт wire-формата (фиксированный массив в
/// `Publish`/`Find`), поэтому константа живёт здесь, а `vecdht-crypto` её реэкспортирует.
pub const DIM: usize = 384;

/// Максимальный размер тела кадра. Ограничение anti-DoS при декоде чужих байтов:
/// `body_len` приходит из сети и без лимита позволяет аллоцировать произвольный размер.
pub const MAX_BODY_LEN: usize = 4 * 1024 * 1024;

/// Максимальная длина variable-length поля (`[u16 len]` в кодировке).
pub const MAX_VAR_LEN: usize = u16::MAX as usize;

#[derive(Debug, Error, PartialEq, Eq)]
pub enum DecodeError {
    #[error("data truncated at offset {offset}")]
    Truncated { offset: usize },
    #[error("trailing bytes at offset {offset}")]
    TrailingBytes { offset: usize },
    #[error("bad enum value {value} for {what} at offset {offset}")]
    BadEnum { value: u64, what: &'static str, offset: usize },
    #[error("duplicate TLV tag {tag}")]
    DuplicateTag { tag: u16 },
    #[error("TLV tags not ascending: {prev} then {next}")]
    TagOrder { prev: u16, next: u16 },
    #[error("unsupported protocol version {0}")]
    Version(u8),
    #[error("reserved flag bits must be zero: {0:#06x}")]
    ReservedFlags(u16),
    #[error("signature flag set but no signature present")]
    SigMissing,
    #[error("signature length {0} not in {{32, 64}}")]
    SigLength(u8),
    #[error("body_len {declared} exceeds cap {cap}")]
    BodyTooLarge { declared: u32, cap: u32 },
    #[error("field too long: {0}")]
    FieldTooLong(usize),
    #[error("list out of contract order at index {index}")]
    OutOfOrder { index: usize },
}

/// Пишет байты по правилам §5.1. Ошибок не бывает: все длины проверяются на стороне чтения.
#[derive(Debug, Default, Clone)]
pub struct Writer {
    buf: Vec<u8>,
    /// Последний записанный TLV-тег; следующий обязан быть больше.
    last_tag: Option<u16>,
}

impl Writer {
    pub fn new() -> Self {
        Self::default()
    }

    #[inline]
    pub fn u8(&mut self, v: u8) -> &mut Self {
        self.buf.push(v);
        self
    }

    #[inline]
    pub fn bool(&mut self, v: bool) -> &mut Self {
        self.u8(u8::from(v))
    }

    #[inline]
    pub fn u16(&mut self, v: u16) -> &mut Self {
        self.buf.extend_from_slice(&v.to_le_bytes());
        self
    }

    #[inline]
    pub fn u32(&mut self, v: u32) -> &mut Self {
        self.buf.extend_from_slice(&v.to_le_bytes());
        self
    }

    #[inline]
    pub fn u64(&mut self, v: u64) -> &mut Self {
        self.buf.extend_from_slice(&v.to_le_bytes());
        self
    }

    /// Массив фиксированной длины — без length-prefix (правило 2).
    #[inline]
    pub fn fixed<const N: usize>(&mut self, v: &[u8; N]) -> &mut Self {
        self.buf.extend_from_slice(v);
        self
    }

    /// Квантованный вектор: ровно `DIM` байтов, без length-prefix.
    #[inline]
    pub fn vec_q(&mut self, v: &[i8; DIM]) -> &mut Self {
        // SAFETY-frei: i8 -> u8 reinterpretation of the same bytes.
        let as_bytes: [u8; DIM] = {
            let mut out = [0u8; DIM];
            for (o, i) in out.iter_mut().zip(v.iter()) {
                *o = *i as u8;
            }
            out
        };
        self.buf.extend_from_slice(&as_bytes);
        self
    }

    /// Variable-length (правило 3).
    #[inline]
    pub fn bytes(&mut self, v: &[u8]) -> &mut Self {
        debug_assert!(v.len() <= MAX_VAR_LEN, "variable field too long");
        self.u16(v.len() as u16);
        self.buf.extend_from_slice(v);
        self
    }

    #[inline]
    pub fn string(&mut self, v: &str) -> &mut Self {
        self.bytes(v.as_bytes())
    }

    /// Список фиксированных элементов с count-prefixом (`u16`), порядок — часть контракта.
    pub fn u16_list(&mut self, v: &[u16]) -> &mut Self {
        self.u16(v.len() as u16);
        for x in v {
            self.u16(*x);
        }
        self
    }

    /// TLV-хвост (правило 4). Теги обязаны идти возрастающе — иначе каноничность байтов
    /// теряется и подпись не воспроизводится.
    pub fn tlv(&mut self, tag: u16, value: &[u8]) -> &mut Self {
        if let Some(prev) = self.last_tag {
            assert!(tag > prev, "TLV tags must ascend: {prev} then {tag}");
        }
        self.last_tag = Some(tag);
        self.u16(tag);
        self.u16(value.len() as u16);
        self.buf.extend_from_slice(value);
        self
    }

    /// Переписать сырые байты без length-prefix. Нужен для заголовка кадра и для
    /// канонического тела при подписи.
    #[inline]
    pub fn extend_raw(&mut self, v: &[u8]) -> &mut Self {
        self.buf.extend_from_slice(v);
        self
    }

    #[inline]
    pub fn len(&self) -> usize {
        self.buf.len()
    }

    #[inline]
    pub fn is_empty(&self) -> bool {
        self.buf.is_empty()
    }

    #[inline]
    pub fn finish(&self) -> Vec<u8> {
        self.buf.clone()
    }

    #[inline]
    pub fn into_vec(self) -> Vec<u8> {
        self.buf
    }
}

/// Читатель поверх чужих байтов. Каждая операция проверяет границы и возвращает offset.
#[derive(Debug, Clone)]
pub struct Reader<'a> {
    data: &'a [u8],
    pos: usize,
}

impl<'a> Reader<'a> {
    pub fn new(data: &'a [u8]) -> Self {
        Self { data, pos: 0 }
    }

    #[inline]
    pub fn remaining(&self) -> usize {
        self.data.len() - self.pos
    }

    #[inline]
    pub fn offset(&self) -> usize {
        self.pos
    }

    fn take(&mut self, n: usize) -> Result<&'a [u8], DecodeError> {
        if self.remaining() < n {
            return Err(DecodeError::Truncated { offset: self.pos });
        }
        let s = &self.data[self.pos..self.pos + n];
        self.pos += n;
        Ok(s)
    }

    #[inline]
    pub fn u8(&mut self) -> Result<u8, DecodeError> {
        Ok(self.take(1)?[0])
    }

    #[inline]
    pub fn bool(&mut self) -> Result<bool, DecodeError> {
        match self.u8()? {
            0 => Ok(false),
            1 => Ok(true),
            other => Err(DecodeError::BadEnum {
                value: other as u64,
                what: "bool",
                offset: self.pos - 1,
            }),
        }
    }

    #[inline]
    pub fn u16(&mut self) -> Result<u16, DecodeError> {
        let s = self.take(2)?;
        Ok(u16::from_le_bytes([s[0], s[1]]))
    }

    #[inline]
    pub fn u32(&mut self) -> Result<u32, DecodeError> {
        let s = self.take(4)?;
        Ok(u32::from_le_bytes([s[0], s[1], s[2], s[3]]))
    }

    #[inline]
    pub fn u64(&mut self) -> Result<u64, DecodeError> {
        let s = self.take(8)?;
        let mut a = [0u8; 8];
        a.copy_from_slice(s);
        Ok(u64::from_le_bytes(a))
    }

    #[inline]
    pub fn fixed<const N: usize>(&mut self) -> Result<[u8; N], DecodeError> {
        let s = self.take(N)?;
        let mut a = [0u8; N];
        a.copy_from_slice(s);
        Ok(a)
    }

    #[inline]
    pub fn vec_q(&mut self) -> Result<[i8; DIM], DecodeError> {
        let raw = self.fixed::<DIM>()?;
        let mut v = [0i8; DIM];
        for (o, i) in v.iter_mut().zip(raw.iter()) {
            *o = *i as i8;
        }
        Ok(v)
    }

    pub fn bytes(&mut self) -> Result<Vec<u8>, DecodeError> {
        let n = self.u16()? as usize;
        if n > MAX_VAR_LEN {
            return Err(DecodeError::FieldTooLong(n));
        }
        Ok(self.take(n)?.to_vec())
    }

    pub fn string(&mut self) -> Result<String, DecodeError> {
        let b = self.bytes()?;
        String::from_utf8(b)
            .map_err(|_| DecodeError::BadEnum { value: 0, what: "utf8", offset: self.pos })
    }

    pub fn u16_list(&mut self) -> Result<Vec<u16>, DecodeError> {
        let n = self.u16()? as usize;
        let mut out = Vec::with_capacity(n.min(4096));
        for _ in 0..n {
            out.push(self.u16()?);
        }
        Ok(out)
    }

    /// Прочитать TLV-хвост до конца тела. Возвращает известные вызывающему пары в порядке
    /// тегов; проверка возрастаания/дублей здесь, игнорирование неизвестных тегов — на стороне
    /// вызывающего (он просто не спрашивает нужный тег).
    pub fn tlv_tail(&mut self) -> Result<Vec<(u16, Vec<u8>)>, DecodeError> {
        let mut out = Vec::new();
        let mut prev: Option<u16> = None;
        while self.remaining() >= 4 {
            let start = self.pos;
            let tag = self.u16()?;
            let len = self.u16()? as usize;
            if let Some(p) = prev {
                if tag == p {
                    return Err(DecodeError::DuplicateTag { tag });
                }
                if tag < p {
                    return Err(DecodeError::TagOrder { prev: p, next: tag });
                }
            }
            prev = Some(tag);
            if len > self.remaining() {
                return Err(DecodeError::Truncated { offset: start });
            }
            let value = self.take(len)?.to_vec();
            out.push((tag, value));
        }
        Ok(out)
    }

    /// Убедиться, что тело разобрано целиком (остаток = ошибка, а не «тихое игнорирование»).
    pub fn expect_end(&self) -> Result<(), DecodeError> {
        if self.remaining() == 0 {
            Ok(())
        } else {
            Err(DecodeError::TrailingBytes { offset: self.pos })
        }
    }

    /// u8-поле, которое обязано быть одним из `allowed` (правило 5).
    pub fn enum_u8_in(&mut self, what: &'static str, allowed: &[u8]) -> Result<u8, DecodeError> {
        let offset = self.pos;
        let v = self.u8()?;
        if allowed.contains(&v) {
            Ok(v)
        } else {
            Err(DecodeError::BadEnum { value: v as u64, what, offset })
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fixed_le_roundtrip() {
        let mut w = Writer::new();
        w.u8(0xAB).u16(0x1234).u32(0xDEAD_BEEF).u64(1 << 40);
        let b = w.into_vec();
        assert_eq!(
            b,
            // 1<<40 в little-endian: единица на байтовом индексе 5 (256^5 = 2^40)
            vec![0xAB, 0x34, 0x12, 0xEF, 0xBE, 0xAD, 0xDE, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00]
        );
        let mut r = Reader::new(&b);
        assert_eq!(r.u8().unwrap(), 0xAB);
        assert_eq!(r.u16().unwrap(), 0x1234);
        assert_eq!(r.u32().unwrap(), 0xDEAD_BEEF);
        assert_eq!(r.u64().unwrap(), 1 << 40);
        r.expect_end().unwrap();
    }

    #[test]
    fn vec_q_preserves_twos_complement() {
        let mut v = [0i8; DIM];
        v[0] = -128;
        v[1] = 127;
        v[2] = -1;
        let mut w = Writer::new();
        w.vec_q(&v);
        let bytes = w.into_vec();
        let mut r = Reader::new(&bytes);
        let back = r.vec_q().unwrap();
        assert_eq!(back, v);
    }

    #[test]
    fn truncation_reports_offset() {
        let b = [1u8, 2, 3];
        let mut r = Reader::new(&b);
        assert_eq!(r.u8().unwrap(), 1);
        assert_eq!(r.u32(), Err(DecodeError::Truncated { offset: 1 }));
    }

    #[test]
    fn tlv_ascending_and_duplicate_rules() {
        let mut w = Writer::new();
        w.u8(9);
        w.tlv(7, &[1]);
        w.tlv(9, &[2, 3]);
        let b = w.into_vec();
        let mut r = Reader::new(&b);
        assert_eq!(r.u8().unwrap(), 9);
        let t = r.tlv_tail().unwrap();
        assert_eq!(t, vec![(7, vec![1u8]), (9, vec![2, 3])]);

        // дубликат тега: [tag:u16, len:u16, body…]
        let dup = [9u8, 7, 0, 1, 0, 0xAA, 7, 0, 1, 0, 0xBB];
        let mut r = Reader::new(&dup);
        r.u8().unwrap();
        assert!(matches!(r.tlv_tail(), Err(DecodeError::DuplicateTag { tag: 7 })));

        // нисходящий тег
        let bad = [9u8, 9, 0, 1, 0, 0xAA, 7, 0, 1, 0, 0xBB];
        let mut r = Reader::new(&bad);
        r.u8().unwrap();
        assert!(matches!(r.tlv_tail(), Err(DecodeError::TagOrder { .. })));
    }

    #[test]
    fn writer_enforces_ascending_tags() {
        let mut w = Writer::new();
        w.tlv(5, &[0]);
        let res = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            w.tlv(4, &[0]);
        }));
        assert!(res.is_err(), "нисходящий тег должен panic'нуть на записи");
    }

    #[test]
    fn trailing_bytes_are_error() {
        let b = [1u8, 2];
        let r = Reader::new(&b);
        assert_eq!(r.expect_end(), Err(DecodeError::TrailingBytes { offset: 0 }));
    }
}
