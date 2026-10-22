//! Оракул `E-0034` (`H-0034`): что делает карта шардов с номером вне диапазона. Пороги
//! зафиксированы в `lab/hypotheses/H-0034-shard-number-admission.md` ДО прогона.
//!
//! Здесь нет сети и корпуса: измеряется поведение `clusters_of_shard` (маска `% NLIST`, граница
//! переполнения `u16`) и, grep'ом в `lab/e0034-run.sh`, распределение диапазонных проверок по
//! сообщениям. Debug-сборка существенна: в release арифметика `u16` кольцевая, и вместо паники
//! переполнения был бы тихий wrap.

use std::panic::{self, AssertUnwindSafe};

use vecdht_crypto::quant::{clusters_of_shard, is_valid_shard};
use vecdht_wire::constants::{CLUSTERS_PER_SHARD, NLIST, SHARDS};

/// Снимает список кластеров и ловит панику переполнения, чтобы граница была видна числом, а не
/// обрывом прогона.
fn try_clusters(shard: u16) -> Result<Vec<u16>, ()> {
    let hook = panic::take_hook();
    panic::set_hook(Box::new(|_| {}));
    let r = panic::catch_unwind(AssertUnwindSafe(|| clusters_of_shard(shard)));
    panic::set_hook(hook);
    r.map_err(|_| ())
}

#[test]
fn an_out_of_range_shard_number_becomes_someone_elses_cluster_list() {
    let probes: [u16; 10] = [0, 1, 63, 64, 80, 128, 1024, 4094, 4095, 65535];

    let mut masked: Vec<String> = Vec::new();
    let mut panicked: Vec<u16> = Vec::new();
    let mut unexpected: Vec<String> = Vec::new();
    let mut empties: Vec<String> = Vec::new();

    for s in probes {
        match try_clusters(s) {
            Err(()) => panicked.push(s),
            Ok(list) => {
                if is_valid_shard(s) {
                    if s >= SHARDS {
                        unexpected.push(format!("{s}: valid по guard, но >= SHARDS"));
                    }
                    continue;
                }
                let same_as = s % SHARDS;
                let reference = clusters_of_shard(same_as);
                if list.is_empty() {
                    // Отдельный класс исхода: в debug его здесь нет вовсе (верхнее множество
                    // паникует), в release это замыкание `base + 16` в 0 — см. E-0036.
                    empties.push(format!("{s}→пусто"));
                } else if list == reference {
                    masked.push(format!("{s}→{same_as}"));
                    // Отдельно проверяем заявленные в пороге (3) пары.
                    if s == 64 {
                        assert_eq!(
                            clusters_of_shard(64),
                            clusters_of_shard(0),
                            "номер 64 обязан совпасть со списком шарда 0"
                        );
                    }
                    if s == 80 {
                        assert_eq!(
                            clusters_of_shard(80),
                            clusters_of_shard(16),
                            "номер 80 обязан совпасть со списком шарда 16"
                        );
                    }
                } else {
                    unexpected.push(format!("{s}: список не равен списку {same_as}"));
                }
            }
        }
    }

    eprintln!(
        "## probes {probes:?}: замаскировано в чужой законный список {} ({}) ##",
        masked.len(),
        masked.join(", ")
    );
    eprintln!(
        "## panic по переполнению u16: {:?}; граница: base_max = {}, шаг = {} ##",
        panicked,
        u16::MAX,
        CLUSTERS_PER_SHARD
    );
    eprintln!("## пустых списков (только release): {} ##", empties.len());
    if !unexpected.is_empty() {
        eprintln!("## непредвиденное: {:?} ##", unexpected);
    }

    // Порог (3): маскированные номера дают побайтово чужой законный список, а не ошибку.
    assert_eq!(
        clusters_of_shard(64),
        clusters_of_shard(0),
        "номер 64 не маскируется в шард 0 — фальсификатор (в)"
    );
    assert_eq!(
        clusters_of_shard(80),
        clusters_of_shard(16),
        "номер 80 не маскируется в шард 16 — фальсификатор (в)"
    );
    assert!(
        unexpected.is_empty(),
        "часть номеров ведёт себя иначе, чем заявлено: {unexpected:?}"
    );

    // Порог (4): граница паники — 4095 (base + 16 = 65_536 не умещается в u16), 4094 ещё жив.
    // Условие профиль-зависимое: паника — это debug-семантика переполнения `u16`. В `release`
    // арифметика кольцевая, и те же номера дают не аварию, а тихий результат; поведение release
    // измерено отдельно в `E-0036` (`shard_number_release.rs`), поэтому здесь в release-профиле
    // проверяется именно его следствие, а не debug-утверждение.
    if cfg!(debug_assertions) {
        assert!(
            try_clusters(4094).is_ok(),
            "при shard = 4094 паники быть не должно — фальсификатор (г)"
        );
        assert!(
            try_clusters(4095).is_err(),
            "при shard = 4095 ожидалась паника переполнения u16 — фальсификатор (г)"
        );
        assert!(
            panicked.contains(&4095) && panicked.contains(&65535),
            "снимок паник не тот: {panicked:?}"
        );
        assert!(empties.is_empty(), "в debug пустых списков быть не должно: {empties:?}");
    } else {
        // Release-ожидание по E-0036: 4095 и 65 535 (= 4095 + 4096·15) замыкают `base + 16` в 0
        // и дают пустой список вместо паники; 4094 остаётся законным списком.
        assert!(
            try_clusters(4094).is_ok(),
            "в release при shard = 4094 список обязан строиться"
        );
        assert_eq!(
            try_clusters(4095),
            Ok(Vec::new()),
            "в release при shard = 4095 ожидался пустой список (E-0036)"
        );
        assert_eq!(
            try_clusters(65535),
            Ok(Vec::new()),
            "в release при shard = 65 535 ожидался пустой список (E-0036)"
        );
        assert!(
            panicked.is_empty(),
            "в release паник быть не должно, а снят снимок: {panicked:?}"
        );
        assert_eq!(
            empties.len(),
            2,
            "в release из десяти probe-номеров пустых списков должно быть два (4095, 65 535): {empties:?}"
        );
        eprintln!("## release-профиль: порог (4) снят в формулировке E-0036 (пустой список вместо паники) ##");
    }

    // Справочно: длина списка всегда 16, NLIST/SHARDS согласованы.
    assert_eq!(clusters_of_shard(0).len(), usize::from(CLUSTERS_PER_SHARD));
    assert_eq!(usize::from(SHARDS) * usize::from(CLUSTERS_PER_SHARD), usize::from(NLIST));
}
