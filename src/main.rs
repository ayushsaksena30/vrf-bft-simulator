mod node;

use std::println;

use ed25519_dalek::SigningKey;
use rand::rngs::OsRng;
use rand::seq::SliceRandom;
use rand::Rng;
use node::{Node};
use hex::encode;
use hmac::{Hmac, KeyInit, Mac};
use sha2::Sha256;

type HmacSha256 = Hmac<Sha256>;

fn main() {

    let mut rng= OsRng{};
    let mut nodes = Vec::new();

    let mut node_index: Vec<u32> = (1..=20).collect();
    node_index.shuffle(&mut rng);

    let malicious_nodes: Vec<u32> = node_index.iter().take(6).cloned().collect();

    for n in 1..=20{
        let node = Node{
            id: n as u32,
            signing_key: SigningKey::generate(&mut rng),
            is_malicious: malicious_nodes.iter().any(|x| x == &n),
            trust_score: 1.0,
        };

        println!("Node id- {}, Public Key- {}",
            node.id, encode(node.signing_key.verifying_key().to_bytes()));
        nodes.push(node);
    }

    let mut number_of_times_malicious_validator=0;

    for round in 1..=1000{

        let mut validators = Vec::new();

        for node in nodes.iter() {
            let vrf_output = compute_vrf(&node, round);
            let is_validator = validator_selection(vrf_output, node.trust_score);
            // println!("Node id- {}, VRF- {}, Is Validator- {}",
                // node.id, vrf_output, is_validator);

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

        for malicious_validator in malicious_validators_id.iter() {
            let random_value: f64 = rng.gen_range(0.0..=1.0);
            if random_value < probability_of_malicious_nodes_getting_caught {
                if let Some(node)=nodes.iter_mut().find(|n| n.id==*malicious_validator){
                    node.trust_score=(node.trust_score-0.2).max(0.15);
                }
            }
        }
        // println!("Validators for round 1: {:?}", validators);
        // println!("Malicious Validators for round 1: {:?}", malicious_validators);
        if !malicious_validators_id.is_empty(){
            number_of_times_malicious_validator+=1;
        }

        for validator_id in validators.iter(){
            if !malicious_validators_id.contains(validator_id){
                if let Some(node)=nodes.iter_mut().find(|n| n.id==*validator_id){
                    node.trust_score=(node.trust_score+0.05).min(2.0);
                }
            }
        }
    }

    println!("Number of times malicious validator was selected: {}", number_of_times_malicious_validator);
    println!("Probability of malicious node selected as validator: {}", number_of_times_malicious_validator as f64 / 1000.0);
}

fn compute_vrf(node: &Node, round: u32) -> u64{
    let key = node.signing_key.to_bytes();
    let mut mac=HmacSha256::new_from_slice(&key).unwrap();
    mac.update(&round.to_be_bytes());
    let res=mac.finalize().into_bytes();

    u64::from_be_bytes(res[0..8].try_into().unwrap())
}

fn validator_selection(vrf_output: u64, trust_score: f64) -> bool {
    let base_rate =0.2;
    let effective_threshold = (u64::MAX as f64)* (1.0-base_rate*trust_score);
    vrf_output > effective_threshold as u64
}