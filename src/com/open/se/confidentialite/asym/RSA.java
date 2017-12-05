package com.open.se.confidentialite.asym;

import java.io.File;
import java.io.FileOutputStream;
import java.io.ObjectOutputStream;
import java.io.UnsupportedEncodingException;
import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;

/**
 * Classe proposant des méthodes de chiffrement et dechiffrement de contenu via
 * l'algorithme AES
 * 
 * @author michael
 *
 */
public class RSA {
	private final String ALGORITHME_RSA = "RSA";

	/**
	 * Répertoire ou seront générées les clés
	 */
	private String keysRepository = "";
	
	public RSA(String generatedKeysRepository){
		this.keysRepository = generatedKeysRepository;
	}
	
	/**
	 * Retourne le chemin d'accès au fichier contenant la clé public
	 * 
	 * @return
	 */
	public String getPublicKeyFile(){
		return this.keysRepository + "/generated-keys/public.key";
	}
	
	/**
	 * Retourne le chemin d'accès au fichier contenant la clé privée
	 * 
	 * @return
	 */
	public String getPrivateKeyFile(){
		return this.keysRepository + "/generated-keys/private.key";
	}
	
	/**
	 * Méthode de génération de la clé publique et de la clé privée
	 */
	public void genererCles() {
		try {
			final KeyPairGenerator keyGen = KeyPairGenerator.getInstance(ALGORITHME_RSA);
			keyGen.initialize(1024);
			final KeyPair key = keyGen.generateKeyPair();

			File privateKeyFile = new File(this.getPrivateKeyFile());
			File publicKeyFile = new File(this.getPublicKeyFile());

			// Create files to store public and private key
			if (privateKeyFile.getParentFile() != null) {
				privateKeyFile.getParentFile().mkdirs();
			}
			privateKeyFile.createNewFile();

			if (publicKeyFile.getParentFile() != null) {
				publicKeyFile.getParentFile().mkdirs();
			}
			publicKeyFile.createNewFile();

			// Enregistrement de la clé publique dans un fichier
			ObjectOutputStream publicKeyOS = new ObjectOutputStream(
					new FileOutputStream(publicKeyFile));
			publicKeyOS.writeObject(key.getPublic());
			publicKeyOS.close();

			// Enregistrement de la clé privée dans un fichier
			ObjectOutputStream privateKeyOS = new ObjectOutputStream(
					new FileOutputStream(privateKeyFile));
			privateKeyOS.writeObject(key.getPrivate());
			privateKeyOS.close();
		} catch (Exception e) {
			e.printStackTrace();
		}

	}
	
	/**
	 * The method checks if the pair of public and private key has been
	 * generated.
	 * 
	 * @return flag indicating if the pair of keys were generated.
	 */
	public boolean areKeysPresent() {

		File privateKey = new File(this.getPrivateKeyFile());
		File publicKey = new File(this.getPublicKeyFile());

		if (privateKey.exists() && publicKey.exists()) {
			return true;
		}
		
		return false;
	}
	  
	/**
	 * La méthode chiffre le contenu en clair passé en paramètre 'message' via la clé publique et
	 * retourne le chiffrement sous la forme d'un tableau de bytes.
	 * 
	 * @param message Message à chiffrer
	 * @param clePublique Clé publique pour chiffrement
	 */
	public byte[] chiffrer(String message, PublicKey clePublique) {

		byte[] messageChiffre = null;

		try {
			// Récupère une instance de Cipher qui permettra le chiffrement RSA
			final Cipher cipher = Cipher.getInstance(ALGORITHME_RSA);
			// Chiffrement du message à partir de la clé publique
			cipher.init(Cipher.ENCRYPT_MODE, clePublique);
			messageChiffre = cipher.doFinal(message.getBytes());

		} catch (InvalidKeyException e) {
			e.printStackTrace();
		} catch (NoSuchAlgorithmException e) {
			e.printStackTrace();
		} catch (NoSuchPaddingException e) {
			e.printStackTrace();
		} catch (IllegalBlockSizeException e) {
			e.printStackTrace();
		} catch (BadPaddingException e) {
			e.printStackTrace();
		}

		return messageChiffre;
	}
	
	/** 
	 * Déchiffrement du message codé (paramètre data) à partir de la clé privée
	 * 
	 * @param data Message chiffré
	 * @param clePrivee Clé privée pour déchiffrement
	 * @return
	 */
	public String dechiffrer(byte[] data, PrivateKey clePrivee) {

		byte[] messageClair = null;
		String message = "";

		try {
			// Récupère une instance de Cipher qui permettra le déchiffrement RSA
			final Cipher cipher = Cipher.getInstance(ALGORITHME_RSA);

			// Déhiffrement du message à partir de la clé privée
			cipher.init(Cipher.DECRYPT_MODE, clePrivee);
			messageClair = cipher.doFinal(data);
			// Convertion tableau de bytes en String
			message = new String(messageClair, "UTF-8");

		} catch (InvalidKeyException e) {
			e.printStackTrace();
		} catch (NoSuchAlgorithmException e) {
			e.printStackTrace();
		} catch (NoSuchPaddingException e) {
			e.printStackTrace();
		} catch (IllegalBlockSizeException e) {
			e.printStackTrace();
		} catch (BadPaddingException e) {
			e.printStackTrace();
		} catch (UnsupportedEncodingException e) {
			e.printStackTrace();
		}

		return message;
	}
}
