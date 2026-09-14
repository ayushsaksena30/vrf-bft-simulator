use ed25519_dalek::SigningKey;

pub struct Node{
    pub id: u32,
    pub signing_key: SigningKey,
    pub is_malicious: bool,
    pub trust_score: f64,
}