use astreuos_transaction::Transaction;
use astro_format::{decode, encode};
use fides::{ed25519, merkle_root};
use opis::Int;
use std::error::Error;

#[derive(Clone, Debug)]
pub struct Block {
    pub accounts_hash: [u8; 32],
    pub chain: Int,
    pub number: Int,
    pub previous_block_hash: [u8; 32],
    pub receipts_hash: [u8; 32],
    pub signature: [u8; 64],
    pub solar_price: Int,
    pub solar_used: Int,
    pub time: Int,
    pub transactions: Vec<Transaction>,
    pub validator: [u8; 32]
}

impl Block {

    pub fn new() -> Self {
        Block {
            accounts_hash: [0_u8; 32],
            chain: Int::zero(),
            number: Int::zero(),
            previous_block_hash: [0_u8; 32],
            receipts_hash: [0_u8; 32],
            signature: [0_u8; 64],
            solar_price: Int::zero(),
            solar_used: Int::zero(),
            time: Int::zero(),
            transactions: Vec::new(),
            validator: [0_u8; 32]
        }
    }

    pub fn body_hash(&self) -> [u8; 32] {
        merkle_root(&vec![
            self.accounts_hash.to_vec(),
            self.chain.to_bytes(),
            self.number.to_bytes(),
            self.previous_block_hash.to_vec(),
            self.receipts_hash.to_vec(),
            self.solar_price.to_bytes(),
            self.solar_used.to_bytes(),
            self.time.to_bytes().to_vec(),
            self.validator.to_vec()
        ])
    }

    pub fn hash(&self) -> [u8; 32] {
        merkle_root(&vec![
            self.body_hash().to_vec(),
            self.signature.to_vec()
        ])
    }

    pub fn transactions_hash(&self) -> [u8; 32] {
        merkle_root(&self.transactions.iter().map(|x| x.hash().to_vec()).collect())
    }

    pub fn from_bytes(arg: &Vec<u8>) -> Result<Block, Box<dyn Error>> {

        let set = decode(&arg);
        
        if set.len() == 12 {
            
            let txs: Vec<Option<Transaction>> = decode(&set[9])
                .iter()
                .map(|x| {
                    match Transaction::from_bytes(x) {
                        Ok(tx) => Some(tx),
                        Err(_) => None
                    }
                })
                .collect();

            if txs.iter().any(|x| x.is_none()) {
                Err("Transactions error!")?
            } else {

                let block = Block {
                    accounts_hash: set[0].clone().try_into().unwrap_or(Err("Accounts hash error!")?),
                    chain: Int::from_bytes(&set[1]),
                    number: Int::from_bytes(&set[2]),
                    previous_block_hash: set[3].clone().try_into().unwrap_or(Err("Previous block hash error!")?),
                    receipts_hash: set[4].clone().try_into().unwrap_or(Err("Receipts hash error!")?),
                    signature: set[5].clone().try_into().unwrap_or(Err("Signature error!")?),
                    solar_price: Int::from_bytes(&set[6]),
                    solar_used: Int::from_bytes(&set[7]),
                    time: Int::from_bytes(&set[8]),
                    transactions: txs.iter().map(|x| x.clone().unwrap()).collect(),
                    validator: set[11].clone().try_into().unwrap_or(Err("Validator error!")?)
                };
                
                match block.verify() {
                    true => Ok(block),
                    false => Err("Verification error!")?
                }

            }
        } else {
            Err("Block error!")?
        }
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        
        encode(&vec![
            self.accounts_hash.to_vec(),
            self.chain.to_bytes(),
            self.number.to_bytes(),
            self.previous_block_hash.to_vec(),
            self.receipts_hash.to_vec(),
            self.signature.to_vec(),
            self.solar_price.to_bytes(),
            self.solar_used.to_bytes(),
            self.time.to_bytes(),
            encode(&self.transactions.iter().map(|x| x.to_bytes()).collect()),
            self.validator.to_vec()

        ])

    }

    pub fn verify(&self) -> bool {

        if self.number == Int::zero() {
            true
        } else {
            ed25519::verify(&self.body_hash(), &self.validator, &self.signature)
        }
    }
}
