### I am building a VRF Validator Selection Simulation in Rust.

### Problem-
The current Decentralized Machine Learning relies on static leader election or fastest node win strategy, which poses significant threats, allowing nodes with better hardware to monopolize gradient validation. 

### Solution-
My work proposes replacing predictable leaders with a Verifiable Random Function (VRF) combined with a dynamic trust scoring system. This ensures that validator selection remains cryptographically unpredictable to attackers while favoring honest nodes.

### Proof-
This project is a Rust simulation of the same concept providing experimental proof that trust score along with VRF selection reduces the probability of selecting a malicious node in the validator committee from 30% random baseline to approximately 16.5% 

### Terminology-
- VRF- Verifiable Random Function
- Validator- A node that validates gradients submitted by other nodes and then help compute the global aggregate.
- Simulation- Representation of something that could exist in real life.
- Node- One system in a distributed environment that has identity, keypair and flag.
- VRF Output- A pseudorandom value computed per node, per round, using that node's secret key and the round number.

### Run locally-
1. Fork the repo
2. Clone the repo
3. Open in your IDE
4. Run `cargo build && cargo run`
### Made by [Ayush Saksena](ayush-saksena.vercel…)