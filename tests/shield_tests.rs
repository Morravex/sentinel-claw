// Copyright 2026 Morravex
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

use sentinel::shield::SecretShield;

#[test]
fn test_entropy_empty_string() {
    assert_eq!(SecretShield::calculate_entropy(""), 0.0);
}

#[test]
fn test_entropy_low_randomness() {
    // Repeating characters have very low entropy
    let low = SecretShield::calculate_entropy("aaaaaaa");
    assert!(low < 1.0, "Expected low entropy for repeated chars, got {}", low);
}

#[test]
fn test_entropy_high_randomness() {
    // A long random-looking string should have high entropy
    let high = SecretShield::calculate_entropy("Xk9Ym7Zp3Wq5Vn4Uo2Tp1Sr0Qs9Pr8On7Nm6Ml5Lk4Kj3Jh2Ig1Hf0Ge");
    assert!(high > 3.5, "Expected high entropy for random-looking string, got {}", high);
}

#[test]
fn test_entropy_natural_language() {
    // Natural language should have moderate entropy (~3.5-4.5 bits)
    let text = "The quick brown fox jumps over the lazy dog";
    let entropy = SecretShield::calculate_entropy(text);
    assert!(entropy > 2.0 && entropy < 5.0, "Expected moderate entropy for natural text, got {}", entropy);
}

#[test]
fn test_known_secret_pattern_openai() {
    // Test string crafted to match the openai regex: sk-[a-zA-Z0-9]{32,72}
    let fake_key = concat!("sk-", "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa");
    assert!(SecretShield::is_known_secret_pattern(fake_key));
}

#[test]
fn test_known_secret_pattern_openrouter() {
    // Test string crafted to match openrouter regex: sk-or-v1-[a-zA-Z0-9\-]{30,}
    let fake_key = concat!("sk-or-v1-", "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaa");
    assert!(SecretShield::is_known_secret_pattern(fake_key));
}

#[test]
fn test_known_secret_pattern_groq() {
    // Test string crafted to match groq regex: gsk_[a-zA-Z0-9]{20,}
    let fake_key = concat!("gsk_", "aaaaaaaaaaaaaaaaaaaa");
    assert!(SecretShield::is_known_secret_pattern(fake_key));
}

#[test]
fn test_known_secret_pattern_anthropic() {
    // Test string crafted to match anthropic regex: sk-ant-[a-zA-Z0-9]{30,}
    let fake_key = concat!("sk-ant-", "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaa");
    assert!(SecretShield::is_known_secret_pattern(fake_key));
}

#[test]
fn test_known_secret_pattern_aws() {
    assert!(SecretShield::is_known_secret_pattern("AKIAIOSFODNN7EXAMPLE"));
}

#[test]
fn test_known_secret_pattern_stripe() {
    let fake_key = concat!("sk_live_", "aaaaaaaaaaaaaaaaaaaaaaaa");
    assert!(SecretShield::is_known_secret_pattern(fake_key));
}

#[test]
fn test_known_secret_pattern_private_key() {
    assert!(SecretShield::is_known_secret_pattern("-----BEGIN RSA PRIVATE KEY-----"));
}

#[test]
fn test_not_secret_pattern() {
    assert!(!SecretShield::is_known_secret_pattern("hello world"));
}

#[test]
fn test_not_secret_plain_text() {
    assert!(!SecretShield::is_known_secret_pattern("This is just a normal sentence with no secrets."));
}

#[test]
fn test_audit_shell_blocks_rm_rf() {
    let risks = SecretShield::audit_shell("rm -rf /");
    assert!(!risks.is_empty(), "Should block rm -rf /");
    assert!(risks.iter().any(|r| r.contains("RISKY_COMMAND") || r.contains("DESTRUCTIVE")));
}

#[test]
fn test_audit_shell_blocks_sudo() {
    let risks = SecretShield::audit_shell("sudo apt install something");
    assert!(!risks.is_empty(), "Should block sudo");
}

#[test]
fn test_audit_shell_blocks_network_recon() {
    let risks = SecretShield::audit_shell("nmap -sV 192.168.1.1");
    assert!(!risks.is_empty(), "Should block nmap");
}

#[test]
fn test_audit_shell_blocks_base64_decode() {
    let risks = SecretShield::audit_shell("echo dGVzdA== | base64 -d");
    assert!(!risks.is_empty(), "Should block base64 decode");
}

#[test]
fn test_audit_shell_blocks_env_access() {
    let risks = SecretShield::audit_shell("cat .env");
    assert!(!risks.is_empty(), "Should block reading .env");
}

#[test]
fn test_audit_shell_blocks_ssh_access() {
    let risks = SecretShield::audit_shell("cat ~/.ssh/id_rsa");
    assert!(!risks.is_empty(), "Should block SSH key access");
}

#[test]
fn test_audit_shell_allows_ls() {
    let risks = SecretShield::audit_shell("ls -la /tmp");
    assert!(risks.is_empty(), "Should allow ls: {:?}", risks);
}

#[test]
fn test_audit_shell_allows_cat_non_restricted() {
    let risks = SecretShield::audit_shell("cat README.md");
    assert!(risks.is_empty(), "Should allow cat on non-restricted files: {:?}", risks);
}

#[test]
fn test_audit_shell_allows_find() {
    let risks = SecretShield::audit_shell("find . -name '*.rs'");
    assert!(risks.is_empty(), "Should allow find: {:?}", risks);
}

#[test]
fn test_audit_shell_blocks_inline_python() {
    let risks = SecretShield::audit_shell("python -c 'import os; os.remove(\"/etc/passwd\")'");
    assert!(!risks.is_empty(), "Should block inline python: {:?}", risks);
}

#[test]
fn test_audit_shell_allows_mv_non_restricted() {
    let risks = SecretShield::audit_shell("mv file1.txt file2.txt");
    assert!(risks.is_empty(), "Should allow mv on non-restricted paths: {:?}", risks);
}

#[test]
fn test_audit_shell_allows_cp_non_restricted() {
    let risks = SecretShield::audit_shell("cp config.toml config.toml.bak");
    assert!(risks.is_empty(), "Should allow cp on non-restricted paths: {:?}", risks);
}

#[test]
fn test_audit_shell_blocks_ifconfig() {
    let risks = SecretShield::audit_shell("ifconfig eth0");
    assert!(!risks.is_empty(), "Should block ifconfig: {:?}", risks);
}

#[test]
fn test_audit_shell_blocks_netstat() {
    let risks = SecretShield::audit_shell("netstat -tlnp");
    assert!(!risks.is_empty(), "Should block netstat: {:?}", risks);
}
