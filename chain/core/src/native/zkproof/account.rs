// CITA
// Copyright 2016-2017 Cryptape Technologies LLC.

// This program is free software: you can redistribute it
// and/or modify it under the terms of the GNU General Public
// License as published by the Free Software Foundation,
// either version 3 of the License, or (at your option) any
// later version.

// This program is distributed in the hope that it will be
// useful, but WITHOUT ANY WARRANTY; without even the implied
// warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR
// PURPOSE. See the GNU General Public License for more details.

// You should have received a copy of the GNU General Public License
// along with this program.  If not, see <http://www.gnu.org/licenses/>.

use rlp::*;
use util::{Address, U256, H256};
use cita_secp256k1::{PrivKey, PubKey, KeyPair};
use cita_secp256k1::keypair::pubkey_to_address;
use rand::os::OsRng;
use std::collections::HashMap;
use rand::{Rng, thread_rng};

use zktx::pedersen_hash;
use zktx::base::*;
use super::{Commitment, Nullifier};
use zktx::p2c::*;
use zktx::c2p::*;

use native::storage::{Serialize, Deserialize};

// Account, complement
#[derive(Default, Debug, Clone, PartialEq)]
pub struct Account {
    addr: Vec<bool>,  // 256
    addr_sk: Vec<bool>, // 256
//    coin: [u64;4],
    balance_pub: String, // less than 128
    balance_priv: String, // less than 128
    rh: Vec<bool>,
}

pub struct Proof (
    ([u64; 6], [u64; 6], bool),
    (([u64; 6], [u64; 6]), ([u64; 6], [u64; 6]), bool),
    ([u64; 6], [u64; 6], bool)
);

impl Serialize for Proof {
    fn serialize(&self) -> Result<Vec<u8>, EvmError> {
        let mut vec: Vec<u8> = Vec::new();
        let bal = self.0;
        let bal_next = self.1;
        let hash = self.2;

        let mut target = [0u8; 8];
        for x in bal.0 {
            x.to_big_endian(&mut target);
            vec.extend(target.iter().cloned());
        }
        for x in bal.1 {
            x.to_big_endian(&mut target);
            vec.extend(target.iter().cloned());
        }
        for x in (bal_next.0).0 {
            x.to_big_endian(&mut target);
            vec.extend(target.iter().cloned());
        }
        for x in (bal_next.0).1 {
            x.to_big_endian(&mut target);
            vec.extend(target.iter().cloned());
        }
        for x in (bal_next.1).0 {
            x.to_big_endian(&mut target);
            vec.extend(target.iter().cloned());
        }
        for x in (bal_next.1).1 {
            x.to_big_endian(&mut target);
            vec.extend(target.iter().cloned());
        }
        for x in hash.0 {
            x.to_big_endian(&mut target);
            vec.extend(target.iter().cloned());
        }
        for x in hash.1 {
            x.to_big_endian(&mut target);
            vec.extend(target.iter().cloned());
        }

        if bal.2 {
            vec.push(1u8);
        } else {
            vec.push(0u8);
        }
        if bal_next.2 {
            vec.push(1u8);
        } else {
            vec.push(0u8);
        }
        if hash.2 {
            vec.push(1u8);
        } else {
            vec.push(0u8);
        }

        Ok(vec)
    }
}

impl Deserialize for Proof {
    fn deserialize(bytes: &Vec<u8>) -> Result<Self, EvmError> {
        let mut bytes_clone = bytes.clone();
        let bool1 = match bytes_clone.pop() {
            Some(0) => false,
            _ => true,
        };

        let bool2 = match bytes_clone.pop() {
            Some(0) => false,
            _ => true,
        };

        let bool3 = match bytes_clone.pop() {
            Some(0) => false,
            _ => true,
        };

        let mut vec_sum: Vec<u64> = u8_2_u64(bytes);
        let mut vec1: Vec<u64> = Vec::new();
        let mut vec2: Vec<u64> = Vec::new();
        let mut vec3: Vec<u64> = Vec::new();
        let mut vec4: Vec<u64> = Vec::new();
        let mut vec5: Vec<u64> = Vec::new();
        let mut vec6: Vec<u64> = Vec::new();
        let mut vec7: Vec<u64> = Vec::new();
        let mut vec8: Vec<u64> = Vec::new();

        for i in 0..vec_sum.len() {
            match i {
                0 ... 6 => vec1.push(vec_sum.get(i)),
                6 ... 12 => vec2.push(vec_sum.get(i)),
                12 ... 18 => vec3.push(vec_sum.get(i)),
                18 ... 24 => vec4.push(vec_sum.get(i)),
                24 ... 30 => vec5.push(vec_sum.get(i)),
                30 ... 36 => vec6.push(vec_sum.get(i)),
                36 ... 42 => vec7.push(vec_sum.get(i)),
                _ => vec8.push(vec_sum.get(i)),
            }
        }

        let proof = Proof(
            (vec1, vec2, bool1),
            ((vec3, vec4), (vec5, vec6), bool2),
            (vec7, vec8, bool3),
        );
        proof
    }
}

//
//impl Encodable for Account {
//    fn rlp_append(&self, s: &mut RlpStream) {
//        s.begin_list(3);
//        s.append(&self.balance);
//        s.append(&self.addr);
//        s.append(&self.prikey)
//    }
//}
//
//impl Decodable for Account {
//    fn decode(r: &UntrustedRlp) -> Result<Self, DecoderError> {
//        if r.item_count()? != 2 {
//            return Err(DecoderError::RlpIncorrectListLen);
//        }
//        Ok(Account {
//            balance: r.val_at(0)?,
//            addr: r.val_at(1)?,
//            prikey: r.val_at(2)?,
//        })
//    }
//}

impl Account {

    pub fn new(&self, sk: Vec<bool>) -> Account {
        let addr = Account::get_addr(sk);
        let mut balance_pub = String::with_capacity(128);
        balance_pub.append("0");
        let balance_priv = Account::priv_balance(&balance_pub);
        let mut rng = thread_rng();
        let r_h = (0..256).map(|_| rng.gen()).collect::<Vec<bool>>();

        Account {
            addr: addr,
            addr_sk: sk,
            balance_pub: balance_pub,
            balance_priv: balance_priv,
            rh: r_h,
        }
    }

    // Get the private balance hash
    pub fn priv_balance(bal: &str) -> [u64; 4] {
        // 256 bit random number
        let r_h = H256::random();
        let one_pad_128 = [1; 128];
        let mut params = Vec::with_capacity(512);
        params.append(one_pad_128.to_owned());
        params.append(bal.as_bytes().to_owned());
        params.append(r_h);
        let balance_priv = pedersen_hash(params);
        balance_priv
    }

    // Get the address from sk
    pub fn get_addr(sk: Vec<bool>) -> Vec<bool> {
        let mut params = Vec::with_capacity(512);
        let one_pad_256 = [1; 256];
        params.append(one_pad_256.to_owned());
        params.append(sk);
        let addr = pedersen_hash(params);
        let address: Vec<bool> = addr.to_owned();
        address
    }

    // Generate the proof from private balance
    pub fn make_commitment(&self, revc: Address, value: &str) -> (Proof, [u64; 4]) {
        let mut rng = thread_rng();
        let rh = self.rh;
//        let rhn = (0..256).map(|_| rng.gen()).collect::<Vec<bool>>();
        let rcm = (0..128).map(|_| rng.gen()).collect::<Vec<bool>>();
        let balance = &self.balance_priv;
        let addr: Vec<bool> = revc.0.into_iter().collect();

        let (proof,hb,coin,delt_ba) = p2c_info(rh,rcm,ba,va,addr).unwrap();

        (proof, coin)
    }

    // Generate nullifier
    // TODO rh需要从链上获取，path和loc怎么从链上获取
    pub fn make_nullifier(&self, value: &str, path: Vec<[u64; 4]>, loc: Vec<bool>) -> (Proof, [u64; 4]) {
        let rh = self.rh;
        let mut rng = thread_rng();
        let rcm = (0..128).map(|_| rng.gen()).collect::<Vec<bool>>();
        let ba = self.balance_priv;
        let addr_sk = self.addr_sk;

        let (proof, nullifier, _, _) = c2p_info(rcm, value, addr_sk, path, loc).unwrap();
        (proof, nullifier)
    }

    // Get the RLP of this commitment.
    pub fn rlp(&self) -> Bytes {
        let mut s = RlpStream::new();
        self.rlp_append(&mut s);
        s.out()
    }

    // Get the crypt_hash (Keccak or blake2b) of this account.
    pub fn rlp_hash(&self) -> H256 {
        self.rlp().crypt_hash()
    }


    pub fn pubkey(&self) -> PubKey {
        let keypair = KeyPair::from_privkey(self.prikey).expect("failed to get pubkey");
        keypair.pubkey()
    }

    pub fn get_address(&self) -> Address {
        let pubkey = self.pubkey();
        pubkey_to_address(&pubkey)
    }

    // generate commitment transaction
    pub fn commitment(&self, value: u64, addr: Address) -> Option<Commitment> {
        if self.balance < value {
            return None;
        }
        let receiver = addr;
        let rand = H256::random();

        let commitment = Commitment {
            receiver: receiver,
            value: value,
            rand: rand,
        };
        Some(commitment)
    }

    // generate nullifier transaction
    // first, confirmed the relevant commitment had been proved
//    pub fn nullifier(&self, comm: Commitment) -> Option<Nullifier> {
//
//    }
}

pub fn u8_2_u64(vec: Vec<u8>) -> Vec<u64> {
    let mut len = vec.len();
    let mut output: Vec<u64> = Vec::new();
    let mut step = 0;
    loop {
        let sl = vec.get(step..step+8).unwrap().into_iter().collect();
        output.push(u8to64(sl));
        step += 8;
        len -= 8;
        if len < 8 {
            break;
        }
    }
    output
}

#[inline(always)]
fn u8to64(nums:[u8;8])->u64{
    let mut res:u64 = 0;
    for i in 0..8{
        res <<=8;
        res |= nums[7-i] as u64;
    }
    res
}
