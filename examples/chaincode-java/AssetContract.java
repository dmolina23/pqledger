// Example: Fabric chaincode (Java). Scanner input only.
package org.example.assets;

import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.Signature;
import javax.crypto.Cipher;
import org.hyperledger.fabric.contract.ContractInterface;

public class AssetContract implements ContractInterface {

    public byte[] fingerprint(byte[] data) throws Exception {
        MessageDigest md = MessageDigest.getInstance("MD5");
        return md.digest(data);
    }

    public void newSigningKey() throws Exception {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
        kpg.initialize(2048);
        kpg.generateKeyPair();
    }

    public Signature signer() throws Exception {
        return Signature.getInstance("SHA256withECDSA");
    }

    public Cipher sealer() throws Exception {
        return Cipher.getInstance("AES/GCM/NoPadding");
    }
}
