pub mod node;

use ed25519_dalek::SigningKey;
use rand::rngs::OsRng;
use rand::seq::SliceRandom;
use rand::Rng;
use node::{Node};
use hex::encode;
use hmac::{Hmac, KeyInit, Mac};
use sha2::Sha256;
use serde::{Serialize, Deserialize};
use wasm_bindgen::prelude::*;

type HmacSha256 = Hmac<Sha256>;

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct RoundSnapshot {
    validators: Vec<u32>,
    slashed_nodes: Vec<u32>,
    trust_scores: Vec<f64>,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct SimulationResult {
    snapshots: Vec<RoundSnapshot>,
    malicious_selection_count: u32,
    probability: f64,
}

#[wasm_bindgen]
pub fn run_simulation(total_nodes: u32, malicious_nodes_count: u32, rounds: u32, base_rate: f64, slash_penalty: Option<f64>, reward_bonus: Option<f64>, trust_floor: Option<f64>, trust_ceil: Option<f64>)->Result<JsValue, JsValue> {
    let mut rng= OsRng{};
    let mut nodes = Vec::new();

    let slash_penalty = slash_penalty.unwrap_or(0.2);
    let reward_bonus = reward_bonus.unwrap_or(0.05);
    let trust_floor = trust_floor.unwrap_or(0.15);
    let trust_ceil = trust_ceil.unwrap_or(2.0);

    let mut node_index: Vec<u32> = (1..=total_nodes).collect();
    node_index.shuffle(&mut rng);

    let malicious_nodes: Vec<u32> = node_index.iter().take(malicious_nodes_count as usize).cloned().collect();

    for n in 1..=total_nodes{
        let node = Node{
            id: n as u32,
            signing_key: SigningKey::generate(&mut rng),
            is_malicious: malicious_nodes.iter().any(|x| x == &n),
            trust_score: 1.0,
        };

        nodes.push(node);
    }

    let mut number_of_times_malicious_validator=0;
    let mut round_snapshots:Vec<RoundSnapshot> = Vec::new();

    for round in 1..=rounds{

        let mut validators = Vec::new();

        for node in nodes.iter() {
            let vrf_output = compute_vrf(&node, round);
            let is_validator = validator_selection(vrf_output, node.trust_score, base_rate);

            if is_validator {
                validators.push(node.id);
            }
        }

        let malicious_validators_id: Vec<u32> = validators.iter().filter(|node| malicious_nodes.contains(node)).cloned().collect();
        let honest_nodes_count = validators.iter().filter(|node| !malicious_nodes.contains(node)).count();

        //simulating probability ofcatching malicious validators based on number of honest validators in the committee
        let probability_of_malicious_nodes_getting_caught= match honest_nodes_count{ 
            0 => 0.0,
            1 => 0.3,
            2..=3 => 0.6,
            _ => 0.9,
        };

        let mut slashed_nodes = Vec::new();

        for malicious_validator in malicious_validators_id.iter() {
            let random_value: f64 = rng.gen_range(0.0..=1.0);
            if random_value < probability_of_malicious_nodes_getting_caught {
                if let Some(node)=nodes.iter_mut().find(|n| n.id==*malicious_validator){
                    node.trust_score=(node.trust_score-slash_penalty).max(trust_floor);
                    slashed_nodes.push(node.id);
                }
            }
        }
        
        if !malicious_validators_id.is_empty(){
            number_of_times_malicious_validator+=1;
        }

        for validator_id in validators.iter(){
            if !malicious_validators_id.contains(validator_id){
                if let Some(node)=nodes.iter_mut().find(|n| n.id==*validator_id){
                    node.trust_score=(node.trust_score+reward_bonus).min(trust_ceil);
                }
            }
        }

        let mut trust_scores = Vec::new();
        for node in nodes.iter(){
            trust_scores.push(node.trust_score);
        }

        round_snapshots.push(RoundSnapshot { validators, slashed_nodes, trust_scores});
    }

    let result = SimulationResult{
        snapshots: round_snapshots,
        malicious_selection_count: number_of_times_malicious_validator,
        probability: (number_of_times_malicious_validator as f64)/(rounds as f64),
    };

    serde_wasm_bindgen::to_value(&result).map_err(|e| JsValue::from_str(&format!("Serialization error: {}", e)))
}

fn compute_vrf(node: &Node, round: u32) -> u64{
    let key = node.signing_key.to_bytes();
    let mut mac=HmacSha256::new_from_slice(&key).unwrap();
    mac.update(&round.to_be_bytes());
    let res=mac.finalize().into_bytes();

    u64::from_be_bytes(res[0..8].try_into().unwrap())
}

fn validator_selection(vrf_output: u64, trust_score: f64, base_rate: f64) -> bool {
    let effective_threshold = (u64::MAX as f64)* (1.0-base_rate*trust_score);
    vrf_output > effective_threshold as u64
}