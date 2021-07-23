from Crypto import PublicKey, Random
from flask import Flask, jsonify, request
from flask_sqlalchemy import SQLAlchemy
from flask_cors import CORS
from flask_marshmallow import Marshmallow
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
import base64 , codecs

rsacal = Flask(__name__)
CORS(rsacal)

#databse connection
rsacal.config['SQLALCHEMY_DATABASE_URI'] = 'mysql://root:danu98@127.0.0.1:3306/rsakey'
rsacal.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(rsacal)
m = Marshmallow(rsacal)


#database creation
class RSAalgorithm2(db.Model):
    id = db.Column(db.Integer, primary_key = True)
    text = db.Column(db.Text())
    publicKey = db.Column(db.Text())
    privateKey = db.Column(db.Text())

    def __init__(self, text, publicKey, privateKey):
        self.text = text
        self.publicKey = publicKey
        self.privateKey = privateKey
        

#database schema
class RSAalgorithmSchema2(m.Schema):
    class Meta:
        fields = ('id', 'text', 'publicKey', 'privateKey')

rsaAlgorithm_schema2 = RSAalgorithmSchema2()
rsaAlgorithms_schema2 = RSAalgorithmSchema2(many=True)

#generate keys 
randomKey_generator = Random.new().read
rsa = RSA.generate(1024, randomKey_generator)
pub_key = rsa.publickey()
    
public_key = pub_key.exportKey()
private_key = rsa.exportKey()

# def encrypt_with_publicKey(msg, pubkey):
#     encryptor = PKCS1_OAEP.new(pubkey)
#     encrpted_msg = encryptor.encrypt(msg)
#     encode = base64.b64encode(encrpted_msg)
#     return encode

# key = RSA.import_key(public_key)
# byte_msg = b'1200|2000.00'

# encoded_msg = encrypt_with_publicKey(byte_msg, key)

#routes - GET all method
@rsacal.route('/get', methods = ['GET'])
def getkeys():
    get_keys = RSAalgorithm2.query.all()
    results = rsaAlgorithms_schema2.dump(get_keys)

    results_list = []
    for i in results:
        results_list.append(i["text"])

    # #decription
    # def decrypt_with_privateKey(msg, prikey):
    #     decryptor = PKCS1_OAEP.new(prikey)
    #     decrpted_msg = decryptor.decrypt(msg)
    #     decode = base64.b64encode(decrpted_msg)
    #     return decode

    # key = RSA.import_key(private_key)
    # str_msg = codecs.decode(results_list[i], 'utf-8')

    # decoded_msg = decrypt_with_privateKey(str_msg, key)

    return jsonify(results_list)

@rsacal.route('/getcolumn', methods = ['GET'])
def getColkeys():
    get_keys = RSAalgorithm2.query.all()
    results = rsaAlgorithms_schema2.dump(get_keys)
    return jsonify(results)



#routes - POST method
@rsacal.route('/hello', methods = ['POST'])
def addtext():
    text = request.json['text']

    #assigning public and private keys
    publicKey = public_key
    privateKey = private_key
    
    #encription
    def encrypt_with_publicKey(msg, pubkey):
        encryptor = PKCS1_OAEP.new(pubkey)
        encrpted_msg = encryptor.encrypt(msg)
        encode = base64.b64encode(encrpted_msg)
        return encode

    #convert into bytes
    key = RSA.import_key(publicKey)
    byte_msg = bytes(text, 'utf-8')
    
    encoded_msg = encrypt_with_publicKey(byte_msg, key)

    text_gen = RSAalgorithm2(encoded_msg, publicKey, privateKey)
    db.session.add(text_gen)
    db.session.commit()
    return rsaAlgorithm_schema2.jsonify(text_gen)


#run debug
if __name__ == "__main__":
    rsacal.run(debug=True)