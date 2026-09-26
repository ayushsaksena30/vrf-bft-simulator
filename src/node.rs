use ed25519_dalek::SigningKey;
use serde::{Serialize, Deserialize};

pub struct Node{
    pub id: u32,
    pub signing_key: SigningKey,
    pub is_malicious: bool,
    pub trust_score: f64,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct NodeInfo{
    pub id: u32,
    pub signing_key: String,
    pub is_malicious: bool,
    pub trust_score: f64,
}