//! E-0112 (`OPEN-V9-10`): `AXIOM_ALLOWLIST` обязан называть третью стандартную аксиому Lean тем
//! именем, которое печатает её же kernel.
//!
//! Дефект двусторонний, и проверка обязана ловить обе стороны:
//!
//! * ложный отказ — квитанция `kind = lean_proof`, честно опирающаяся на `Quot.sound` (имя из
//!   `src/Init/Prelude.lean:543`, и именно его kernel печатает в `#print axioms`), получает
//!   `E_AXIOM_NOT_ALLOWED`, то есть протокол отвергает доказательство, которое отвергать не за что;
//! * ложное принятие — список содержит `Quoted.sound`, имени, которое kernel выдать не может ни
//!   при какой программе. Пока оно в allowlist, прибор принимает строку, не соответствующую ни
//!   одному реальному выводу Lean, и «сверка с kernel» превращается в сверку с выдуманным именем.
//!
//! Поэтому здесь четыре факта, а не один: принятие честного имени, отказ выдуманного, контроль
//! пустого списка (чтобы первые два не оказались следствием обеих веток из-за посторонней ошибки
//! валидации) и отказ не-Lean класса, назвавшего аксиомы (§V9.5, правило 4).
//!
//! Имя, которое печатает kernel, в этом тесте не берётся из строки Rust-кода: helper прогона
//! спрашивает его у `lean` отдельным файлом-свидетелем и сверяет с напечатанным здесь
//! `V912_ALLOWLIST=`. Тест же проверяет, что множество ведёт себя так, как будто имя правильное, —
//! то есть ловит расхождение между правилом вывода вердикта и тем, что называется в ядре.
//!
//! Воспроизведение:
//!     cargo test -q -p vecdht-orders --test v912_axiom_names -- --nocapture

use vecdht_orders::*;

fn pattern(v: u8) -> Hash {
    [v; 32]
}

/// Заказы, подачи и квитанции собираются теми же вызовами, что и в генераторе векторов: этот тест
/// не имеет права на собственную трактовку полей.
fn order(kind: Kind) -> PaidOrder {
    let (sk, vk) = keypair(1);
    let statement = normalize_statement(
        b"theorem add_zero_right (n : Nat) : n + 0 = n := by\n  induction n with\n    | zero => rfl\n    | succ k ih => simp [Nat.succ_add, ih]\n",
    )
    .unwrap();
    let mut o = PaidOrder {
        kind,
        statement_hash: statement_hash(kind, &statement).unwrap(),
        statement,
        verifier: VerifierSpec {
            image_digest: pattern(0x2a),
            entrypoint: "/usr/local/bin/verify".to_string(),
            budget_seconds: 120,
            network: false,
        },
        reward: Reward {
            amount: 1_000_000,
            asset: Asset::Native,
            escrow_ref: b"vecdht:escrow/0x01".to_vec(),
        },
        deadline: 1_800_000_000,
        submit_limit: 8,
        publisher: *vk.as_bytes(),
        nonce: 7,
        signature: None,
    };
    o.sign(&sk);
    o
}

fn submission(o: &PaidOrder) -> Submission {
    let (sk, vk) = keypair(2);
    let files = vec![ArtifactFile {
        path: "Proof.lean".to_string(),
        content_sha256: pattern(0x11),
    }];
    let mut s = Submission {
        order_ref: o.order_ref(),
        artifact_hash: artifact_set_hash(&files).unwrap(),
        artifact_uri: "ipfs://bafybeiexample".to_string(),
        submitter: *vk.as_bytes(),
        nonce: 1,
        created_at: 1_799_999_999,
        signature: None,
    };
    s.sign(&sk);
    s
}

fn receipt(o: &PaidOrder, s: &Submission, axioms: &[&str]) -> Receipt {
    let (sk, vk) = keypair(3);
    let mut r = Receipt {
        order_ref: o.order_ref(),
        submission_ref: s.submission_ref(),
        verdict: Verdict::Pass,
        image_digest: o.verifier.image_digest,
        toolchain: "leanprover/lean4:v4.36.0-rc1".to_string(),
        axioms: axioms.iter().map(|a| a.to_string()).collect(),
        wall_clock_ms: 41_000,
        budget_ms: u64::from(o.verifier.budget_seconds) * 1_000,
        exit_code: 0,
        stdout_sha256: pattern(0x33),
        stderr_sha256: pattern(0x44),
        deterministic: true,
        verifier_pubkey: *vk.as_bytes(),
        signature: None,
    };
    r.sign(&sk);
    r
}

/// Непустой список аксиом у не-Lean класса — отдельная ветка §V9.5: она обязана остаться
/// запретной и после правки имени, иначе правка «по ходу дела» сняла бы ещё одно правило.
fn non_lean_names_axioms() -> bool {
    let o = order(Kind::ReproRun);
    let s = submission(&o);
    let (_ver_sk, ver_vk) = keypair(3);
    let r = receipt(&o, &s, &["Quot.sound"]);
    r.validate(&o, &s, &ver_vk).is_err()
}

#[test]
fn v912_axiom_allowlist_matches_the_kernel_name() {
    let o = order(Kind::LeanProof);
    let s = submission(&o);
    let (_ver_sk, ver_vk) = keypair(3);

    println!("V912_ALLOWLIST_SIZE={}", AXIOM_ALLOWLIST.len());
    println!("V912_ALLOWLIST={}", AXIOM_ALLOWLIST.join("|"));

    // (а) честное имя ядра: все три стандартные аксиомы Lean 4, как их называет kernel.
    let honest = receipt(&o, &s, &["propext", "Classical.choice", "Quot.sound"]);
    let honest_ok = honest.validate(&o, &s, &ver_vk).is_ok();
    println!(
        "V912_HONEST_QUOT_ACCEPTED={}",
        u8::from(honest_ok)
    );

    // (б) выдуманное имя: его не produzhit ни один kernel, значит оно не должно быть разрешено.
    let fake = receipt(&o, &s, &["Quoted.sound"]);
    let fake_rejected = match fake.validate(&o, &s, &ver_vk) {
        Err(e) => e.code == ErrorCode::E_AXIOM_NOT_ALLOWED,
        Ok(_) => false,
    };
    println!("V912_FAKE_QUOTED_REJECTED={}", u8::from(fake_rejected));

    // (в) контроль: пустой список проходит, значит (а) и (б) различает именно правило об аксиомах,
    // а не посторонняя ошибка валидации (подпись, бюджет, digest).
    let empty = receipt(&o, &s, &[]);
    let empty_ok = empty.validate(&o, &s, &ver_vk).is_ok();
    println!("V912_EMPTY_AXIOM_CONTROL={}", u8::from(empty_ok));

    // (г) правка имени не должна попутно открыть ветку «не-Lean класс назвал аксиомы».
    let non_lean = non_lean_names_axioms();
    println!("V912_NONLEAN_NAMES_AXIOMS={}", u8::from(non_lean));

    // (д) то же самое множество, названное строками: сверка с выводом `lean` живёт в helper'е, а
    // здесь — прямое требование, что в allowlist есть ядро-имя и нет выдуманного.
    let has_quot = AXIOM_ALLOWLIST.contains(&"Quot.sound");
    let has_quoted = AXIOM_ALLOWLIST.contains(&"Quoted.sound");
    println!("V912_ALLOWLIST_HAS_QUOT_SOUND={}", u8::from(has_quot));
    println!("V912_ALLOWLIST_HAS_QUOTED_SOUND={}", u8::from(has_quoted));

    let all_ok = honest_ok
        && fake_rejected
        && empty_ok
        && non_lean
        && has_quot
        && !has_quoted;
    println!("V912_ALL_OK={}", u8::from(all_ok));
    assert!(
        all_ok,
        "allowlist аксиом расходится с именем, которое печатает kernel Lean: \
         честная квитанция принята={honest_ok}, выдуманное имя отвергнуто={fake_rejected}, \
         контроль пустого списка={empty_ok}, не-Lean с аксиомами отвергнут={non_lean}"
    );
}
