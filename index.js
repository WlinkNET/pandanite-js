const Big       = require("big.js"); // float safe math
const axios = require('axios'); // <!!!!  got@11 specific version
const nacl = require('tweetnacl');
const { decodeUTF8, decodeHex } = require('tweetnacl-util');
const CryptoJS = require('react-native-crypto-js');
const bip39     = require('bip39');
const { Buffer } = require('buffer');

class PandaniteApi {

    /*
    
        Typical host format for bamboo node is http://xxx.xxx.xxx.xxx:3000
        
        All api calls return promises
    
    */

    constructor(host) {
    
        this.apiUrl = host;

    }

    /*
    
        get current network status
    
    */
    
        getNetworkInfo() {
            return new Promise((resolve, reject) => {
                (async () => {
                    try {
                        const response = await axios.get(this.apiUrl + "/block_count");
                        const height = response.data;
        
                        const version = 1;
        
                        const blockInfoResponse = await axios.get(this.apiUrl + `/blocks_info/${height}`);
                        const blockinfo = blockInfoResponse.data;
        
                        // Base Response, you may add additional info
                        const inforesponse = {
                            version: version,
                            blockheight: height,
                            lastblock: blockinfo.blocktime
                        };
        
                        resolve(inforesponse);
        
                    } catch (e) {
                        reject(e);
                    }
                })();
            });
        }
    
    /*
    
        get block information by height
    
    */

        getBlock(blockheight) {
            return new Promise((resolve, reject) => {
                (async () => {
                    try {
                        const response = await axios.get(this.apiUrl + "/block?blockId=" + blockheight);
                        const body = response.data;
        
                        if (body && body.id) {
                            const unhexlify = function(str) {
                                const result = [];
                                while (str.length >= 2) {
                                    result.push(parseInt(str.substring(0, 2), 16));
                                    str = str.substring(2, str.length);
                                }
                                return new Uint8Array(result);
                            };
        
                            const generateBlockHash = function(block) {
                                let wordArray1 = CryptoJS.enc.Hex.parse(block["merkleRoot"]);
                                let wordArray2 = CryptoJS.enc.Hex.parse(block["lastBlockHash"]);
                                let hexdiff = (parseInt(block["difficulty"]).toString(16).padStart(8, '0'));
                                let hexdiffa = hexdiff.split('').reverse().join('');
                                let wordArray3 = CryptoJS.enc.Hex.parse(hexdiffa);
                                let hextimestamp = (parseInt(block["timestamp"]).toString(16).padStart(16, '0'));
                                let hextimestampa = hextimestamp.split('').reverse().join('');
                                let wordArray4 = CryptoJS.enc.Hex.parse(hextimestampa);
        
                                let combinedArray = wordArray1.concat(wordArray2).concat(wordArray3).concat(wordArray4);
                                let combinedWordArray = CryptoJS.lib.WordArray.create(combinedArray);
        
                                let blockHash = CryptoJS.SHA256(combinedWordArray).toString(CryptoJS.enc.Hex);
                                return blockHash;
                            };
        
                            const inforesponse = {
                                height: body.id,
                                blockhash: generateBlockHash(body),
                                blocktime: new Date(body.timestamp * 1000),
                                transactions: body.transactions,
                                raw: body
                            };
        
                            resolve(inforesponse);
                        } else {
                            reject("Not Found");
                        }
                    } catch (e) {
                        reject(e);
                    }
                })();
            });
        }
    
    /*
    
        Transaction information returned in a "bitcoiny" type format
    
    */

        getTransaction(transactionid) {
            return new Promise((resolve, reject) => {
                (async () => {
                    try {
                        transactionid = transactionid.toUpperCase();
        
                        // Axios POST request
                        const response = await axios.post(this.apiUrl + "/verify_transaction", {
                            txid: transactionid
                        });
                        const body = response.data;
        
                        var seederAddress = "";
        
                        if (body[0].status == "IN_CHAIN") {
                            let blockInfo;
                            let blockTrx = [];
                            
                            try {
                                blockInfo = await this.getBlock(body[0].blockId);
                                blockTrx = blockInfo.transactions;
                            } catch (e) {
                                reject('Not Found');
                            }
        
                            for (let i = 0; i < blockTrx.length; i++) {
                                let thisTx = blockTrx[i];
                                if (thisTx.txid == transactionid && thisTx.from != seederAddress) {
                                    var tdetails = [];
                                    var ddetails = {
                                        amount: Big(thisTx.amount).div(10**4).toFixed(4),
                                        fee: Big(thisTx.fee).div(10**4).toFixed(4),
                                        type: thisTx.from==''?"generate":"transfer",
                                        fromaddress: thisTx.from,
                                        toaddress: thisTx.to
                                    };
        
                                    tdetails.push(ddetails);
        
                                    var confirmations = 0;
                                    try {
                                        var currentNetworkInfo = await this.getNetworkInfo();
                                        confirmations = currentNetworkInfo.blockheight - blockInfo.height;
                                    } catch (e) {}
        
                                    var status = 'pending';
                                    if (confirmations > 0) status = 'confirmed';
                                    if (confirmations < 0) status = 'error';
        
                                    var transinfo = {
                                        totalamount: Big(thisTx.amount).div(10**4).toFixed(4),
                                        blockhash: blockInfo.blockhash,
                                        blocknumber: blockInfo.height,
                                        txid: thisTx.txid,
                                        id: thisTx.txid,
                                        fee: Big(thisTx.fee).div(10**4).toFixed(4),
                                        status: status,
                                        confirmations: confirmations,
                                        timestamp: {
                                            human: new Date(thisTx.timestamp * 1000).toLocaleString("en-US"),
                                            unix: parseInt(thisTx.timestamp)
                                        },
                                        details: tdetails,
                                        raw: thisTx
                                    };
        
                                    resolve(transinfo);
                                    return; // Ensure we exit the loop and the function once the transaction is found
                                }
                            }
                            reject('Not Found');
                        } else {
                            reject('Not Found');
                        }
                    } catch (e) {
                        reject(e);
                    }
                })();
            })
        }
    
    /*
    
        Returns human readable balance for an address
    
    */

        getBalance(address) {
            return new Promise((resolve) => {
                (async () => {
                    try {
                        const response = await axios.get(`${this.apiUrl}/ledger?wallet=${address}`);
                        if (response.data) {
                            const balance = Big(response.data.balance).div(10**4).toFixed(8);
                            resolve(balance);
                        } else {
                            resolve("0");
                        }
                    } catch (e) {
                        resolve("0");
                    }
                })();
            })
        }
    

    
    /*
    
        fee just seems to be a static 0.0001 right now
    
    */

    getFeeEstimate() {
        return new Promise((resolve, reject) => {
            (async () => {

                try {

                    var feeestimate = '0.0001';
                    
                    resolve(feeestimate);

                } catch (e) {
                    reject(e);
                }
                
            })();
        })
    }
    
    /*
    
        signedTxArray:   an array of signed transactions created using bamboo crypto
    
    */
    
        submitTransaction(signedTxArray) {
            return new Promise((resolve, reject) => {
                (async () => {
                    try {
                        const response = await axios.post(`${this.apiUrl}/add_transaction_json`, signedTxArray);
                        if (response.data) {
                            resolve(response.data);
                        } else {
                            reject(new Error('No data received from the server.'));
                        }
                    } catch (e) {
                        reject(e);
                    }
                })();
            })
        }

    /*
    
        Get all transactions for a given address
    
    */
        getTransactionsForAddress(address) {
            return new Promise((resolve, reject) => {
                (async () => {
                    const checkAddress = function(transaction) {
                        return transaction.to == address || transaction.from == address;
                    }
        
                    try {
                        let transactionList = [];
        
                        const accountTransactionsResponse = await axios.get(`${this.apiUrl}/wallet_transactions?wallet=${address}`);
                        let getaccountTransactions = accountTransactionsResponse.data;
                        getaccountTransactions.sort((a, b) => b.timestamp - a.timestamp);
                        transactionList = getaccountTransactions.filter(checkAddress);
        
                        const pendingTransactionsResponse = await axios.get(`${this.apiUrl}/tx_json`);
                        let pendingTransactions = pendingTransactionsResponse.data.filter(checkAddress);
        
                        for (let i = 0; i < pendingTransactions.length; i++) {
                            let thisTx = pendingTransactions[i];
                            thisTx.pending = true;
                            transactionList.unshift(thisTx);
                        }
        
                        resolve(transactionList);
                    } catch (e) {
                        reject(e);
                    }
                })();
            })
        }
    
    /*
    
        filter is an array of addresses you would like to get a report on..  presumably addresses you own or ALL of you leave it empty
    
    */
        getRecentTransactions(filter = [], blocksBack = 5) {
            return new Promise((resolve, reject) => {
                (async () => {
                    try {
                        const lastBlockResponse = await axios.get(`${this.apiUrl}/block_count`);
                        const lastblock = lastBlockResponse.data;
        
                        if (lastblock && lastblock > 0) {
                            let newtxlist = [];
                            const fromblock = lastblock - blocksBack;
                            const toblock = lastblock;
        
                            for (let i = fromblock; i <= toblock; i++) {
                                let blockInfo;
                                try {
                                    const blockInfoResponse = await axios.get(`${this.apiUrl}/block?blockId=${i}`);
                                    blockInfo = blockInfoResponse.data;
                                } catch (e) {
                                    // Handle any errors here if necessary
                                }
        
                                if (blockInfo && blockInfo.transactions) {
                                    for (let j = 0; j < blockInfo.transactions.length; j++) {
                                        const txinfo = blockInfo.transactions[j];
                                        if (filter.length === 0 || filter.includes(txinfo.to) || filter.includes(txinfo.from)) {
                                            const confirmations = lastblock - i;
                                            const newtx = {
                                                id: txinfo.txid.toUpperCase(),
                                                fromAddress: txinfo.from,
                                                toAddress: txinfo.to,
                                                type: txinfo.from === '' ? "generate" : "transfer",
                                                amount: Big(txinfo.amount).div(10**4).toFixed(4),
                                                fee: Big(txinfo.fee).div(10**4).toFixed(4),
                                                confirmations: confirmations
                                            };
                                            newtxlist.push(newtx);
                                        }
                                    }
                                }
                            }
                            resolve(newtxlist);
                        } else {
                            reject("Unable to get last block count");
                        }
                    } catch (e) {
                        reject(e);
                    }
                })();
            });
        }

}

class PandaniteCrypto {

    constructor() {

    }
    
    /*

        generates a new address - should store the sensitive stuff encrypted
        
    */

        generateNewAddress(password = "") {

            const pad = (n, width, z) => {
                z = z || '0';
                n = n + '';
                return n.length >= width ? n : new Array(width - n.length + 1).join(z) + n;
            }
        
            try {
                const entropy = CryptoJS.lib.WordArray.random(16).toString();
                const mnemonic = bip39.entropyToMnemonic(entropy);
                const seed = bip39.mnemonicToSeedSync(mnemonic, password);
                
                const seedhash = CryptoJS.SHA256(seed).toString(CryptoJS.enc.Hex);
                
                const keyPair = nacl.sign.keyPair.fromSeed(Uint8Array.from(Buffer.from(seedhash, 'hex')));
        
                const bpublicKey = Buffer.from(keyPair.publicKey);
        
                const hash = CryptoJS.SHA256(bpublicKey).toString(CryptoJS.enc.Hex);
                const hash2 = CryptoJS.RIPEMD160(hash).toString(CryptoJS.enc.Hex);
                const hash3 = CryptoJS.SHA256(hash2).toString(CryptoJS.enc.Hex);
                const hash4 = CryptoJS.SHA256(hash3).toString(CryptoJS.enc.Hex);
        
                const checksum = hash4.substring(0, 2);
        
                let addressArray = ['00', ...Array.from(Buffer.from(hash2, 'hex').map(byte => pad(byte.toString(16), 2))), ...Array.from(Buffer.from(hash4, 'hex').slice(0, 4).map(byte => pad(byte.toString(16), 2)))];
                const address = addressArray.join('').toUpperCase();
        
                const newAccount = {
                    address: address,
                    seed: seed.toString("hex").toUpperCase(),
                    mnemonic: mnemonic,
                    seedPassword: password,
                    publicKey: Buffer.from(keyPair.publicKey).toString("hex").toUpperCase(),
                    privateKey: Buffer.from(keyPair.secretKey).toString("hex").toUpperCase()
                };
                
                return newAccount;
        
            } catch (e) {
                console.log(e);
                return false;
            }
        }
    
        generateAddressFromMnemonic(mnemonic, password = "") {

            let isValid = bip39.validateMnemonic(mnemonic);
        
            if (isValid == false) {
                return false;
            } else {
                const pad = function(n, width, z) {
                    z = z || '0';
                    n = n + '';
                    return n.length >= width ? n : new Array(width - n.length + 1).join(z) + n;
                }
        
                try {
                    let seed = bip39.mnemonicToSeedSync(mnemonic, password);
        
                    let seedhash = CryptoJS.SHA256(CryptoJS.lib.WordArray.create(seed)).toString(CryptoJS.enc.Hex);
        
                    // Using tweetnacl for key pair generation
                    let keyPair = nacl.sign.keyPair.fromSeed(new Uint8Array(seedhash.match(/[\da-f]{2}/gi).map(function (h) {
                        return parseInt(h, 16)
                    })));
        
                    let bpublicKey = keyPair.publicKey;
        
                    let hash = CryptoJS.SHA256(CryptoJS.lib.WordArray.create(bpublicKey)).toString(CryptoJS.enc.Hex);
                    let hash2 = CryptoJS.RIPEMD160(hash).toString(CryptoJS.enc.Hex);
                    let hash3 = CryptoJS.SHA256(hash2).toString(CryptoJS.enc.Hex);
                    let hash4 = CryptoJS.SHA256(hash3).toString(CryptoJS.enc.Hex);
        
                    let checksum = hash4[0];
        
                    let addressArray = [];
                    addressArray[0] = '00';
                    for(let i = 1; i <= 20; i++) {
                        addressArray[i] = pad(hash2[i-1].toString(16), 2);
                    }
                    addressArray[21] = pad(hash4[0].toString(16), 2);
                    addressArray[22] = pad(hash4[1].toString(16), 2);
                    addressArray[23] = pad(hash4[2].toString(16), 2);
                    addressArray[24] = pad(hash4[3].toString(16), 2);
        
                    let address = addressArray.join('').toUpperCase();
        
                    let newAccount = {
                        address: address,
                        seed: seed.toString("hex").toUpperCase(),
                        mnemonic: mnemonic,
                        seedPassword: password,
                        publicKey: Array.from(keyPair.publicKey).map(byte => ('0' + (byte & 0xFF).toString(16)).slice(-2)).join('').toUpperCase(),
                        privateKey: Array.from(keyPair.secretKey).map(byte => ('0' + (byte & 0xFF).toString(16)).slice(-2)).join('').toUpperCase()
                    };
                    
                    return newAccount;
        
                } catch (e) {
                    console.error(e);
                    return false;
                }
            }
        }
    
    /*
    
        just a regex test to make sure it is 50 characters hex
    
    */
    
    validateAddress(address) {

        try {

            var pattern = /^[a-fA-F0-9]{50}$/;
            
            var isvalid = pattern.test(address);
            
            return isvalid;

        } catch (e) {
            return false;
        }

    }
    
    /*
    
        create and sign a transaction for submitting to the api
    
    */
    
        createSignedTransaction(toAddress, humanAmount, publicKey, privateKey) {
    
            if (this.validateAddress(toAddress) == false) return false;
        
            const pad = function(n, width, z) {
                z = z || '0';
                n = n + '';
                return n.length >= width ? n : new Array(width - n.length + 1).join(z) + n;
            }
        
            const unhexlify = function(str) { 
                let result = [];
                while (str.length >= 2) { 
                    result.push(parseInt(str.substring(0, 2), 16));
                    str = str.substring(2, str.length);
                }
                return new Uint8Array(result);
            }
                            
            let formatAmount = parseInt(Big(humanAmount).times(10**4).toFixed(0));
            let nonce = Date.now();
            let fee = 1;
        
            let keyPair = nacl.sign.keyPair.fromSeed(Buffer.from(privateKey, 'hex'));
        
            let trxTimestamp = Date.now();
        
            let hash = CryptoJS.SHA256(CryptoJS.enc.Hex.parse(publicKey)).toString();
            let hash2 = CryptoJS.RIPEMD160(hash).toString();
            let hash3 = CryptoJS.SHA256(hash2).toString();
            let hash4 = CryptoJS.SHA256(hash3).toString();
        
            let checksum = hash4[0];
        
            let addressArray = [];
        
            addressArray[0] = '00';
            for(let i = 1; i <= 20; i++) {
                addressArray[i] = pad(hash2[i-1].toString(16), 2);
            }
            for(let i = 21; i <= 24; i++) {
                addressArray[i] = pad(hash4[i-21].toString(16), 2);
            }
        
            let fromAddress = addressArray.join('').toUpperCase();
                
            let tx = {
                "from": fromAddress, 
                "to": toAddress, 
                "fee": fee,
                "amount": formatAmount, 
                "timestamp": trxTimestamp
            };
        
            let ctx = CryptoJS.SHA256(
                unhexlify(tx["to"]).concat(
                    unhexlify(tx["from"]),
                    unhexlify(pad(tx["fee"].toString(16), 16)),
                    unhexlify(pad(tx["amount"].toString(16), 16)),
                    unhexlify(pad(tx["timestamp"].toString(16), 16))
                )
            ).toString();
        
            let signature = nacl.sign.detached(ctx, keyPair.secretKey);
        
            let tx_json = {
                "amount": tx.amount, 
                "fee": tx.fee, 
                "from": tx.from,
                "signature": Buffer.from(signature).toString('hex').toUpperCase(),
                "signingKey": publicKey, 
                "timestamp": String(tx.timestamp),
                "to": tx.to
            };
        
            return tx_json;
        }
    
    /*
    
        Sign a message using your keyPair
    
    
    */
    
    signMessage(message, publicKey, privateKey) {
    
        try {

            let keyPair = {
                publicKey: Buffer.from(publicKey, 'hex'),
                privateKey: Buffer.from(privateKey, 'hex')
            }

            let signature = ed25519.Sign(Buffer.from(message, 'utf8'), keyPair); //Using Sign(Buffer, Keypair object)

            let sig2 = signature.toString('hex').toUpperCase();
            
            return sig2;


        } catch (e) {

            return false;

        }
    
    }

    /*
    
        Validate a message using publickey and signature
    
    
    
    
    verifyMessage(message, publicKey, signature) {
    
        if (ed25519.Verify(Buffer.from(message, 'utf8'), Buffer.from(signature, 'hex'), Buffer.from(publicKey, 'hex'))) {
        
            return true;
            
        } else {
        
            return false;
            
        }
    
    }
    */
    verifyMessage(message, publicKey, signature) {
        const messageUint8 = decodeUTF8(message);
        const publicKeyUint8 = decodeHex(publicKey);
        const signatureUint8 = decodeHex(signature);
    
        if (nacl.sign.detached.verify(messageUint8, signatureUint8, publicKeyUint8)) {
          return true;
        } else {
          return false;
        }
      }

    /*
    
        Validate a message using publickey and signature
    
    
    */
    
        walletAddressFromPublicKey(publicKey) {
            try {
              const pad = function(n, width, z) {
                z = z || '0';
                n = n + '';
                return n.length >= width ? n : new Array(width - n.length + 1).join(z) + n;
              };
        
              let bpublicKey = Buffer.from(publicKey, 'hex');
              let hash = CryptoJS.SHA256(bpublicKey).toString(CryptoJS.enc.Hex);
              let hash2 = CryptoJS.RIPEMD160(hash).toString(CryptoJS.enc.Hex);
              let hash3 = CryptoJS.SHA256(hash2).toString(CryptoJS.enc.Hex);
              let hash4 = CryptoJS.SHA256(hash3).toString(CryptoJS.enc.Hex);
        
              let checksum = parseInt(hash4.substring(0, 2), 16);
        
              let address = ['00'];
              for (let i = 0; i < hash2.length; i += 2) {
                address.push(pad(hash2.substr(i, 2), 2));
              }
        
              address.push(pad(checksum.toString(16), 2));
              address.push(hash4.substr(2, 2));
              address.push(hash4.substr(4, 2));
              address.push(hash4.substr(6, 2));
        
              return address.join('').toUpperCase();
            } catch (e) {
              return false;
            }
          }

}

module.exports = {api: PandaniteApi, crypto: PandaniteCrypto};
