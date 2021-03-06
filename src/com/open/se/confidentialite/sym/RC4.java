package com.open.se.confidentialite.sym;

import java.io.UnsupportedEncodingException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.KeyGenerator;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

/**
 * Classe proposant des méthodes de chiffrement et dechiffrement de contenu via
 * l'algorithme RC4
 * 
 * *****************************************************************************************************
 * NOTE : L'ALGORITHME RC4 ETANT PEU SUR, ON NE L'UTILISERA PAS DANS LES DEV. UTILISER AES A LA PLACE.
 * ***************************************************************************************************** 
 * @author michael
 *
 */
public class RC4 {

	private final String ALGORITHME_RC4 = "RC4";
	
	/**
	 * La méthode chiffre le contenu en clair passé en paramètre 'message' et
	 * retourne le chiffrement sous la forme d'un tableau de bytes.
	 * Deux options sont possibles concernant la clé utilisée pour chiffrer :
	 * 		1 - Soit la clé passée en paramètre de la méthode est valorisée et on l'utilisera
	 * 			pour le chiffrement
	 * 		2 - Soit la clé passée en paramètre est à null et l'on utilisera une génération
	 * 			automatique de la clé
	 * 
	 * NOTE : 
	 * @param message
	 * @param cle
	 */
	public byte[] chiffrer(String message, String cle) {
	
		SecretKey secretKey = null;
		byte[] messageChiffre = null;
		
		try {
			// Obtention d'un objet SecretKey qui contient la clé pour chiffrer le message. 
			// Soit on fourni la clé de chiffrement, soit on la génère via KeyGenerator
			if (cle != null){
				secretKey = new SecretKeySpec(cle.getBytes(), ALGORITHME_RC4);
			}else{
				KeyGenerator keyGen = KeyGenerator.getInstance(ALGORITHME_RC4);
				keyGen.init(128);
				secretKey = keyGen.generateKey();
			}
						
			// Récupère une instance de Cipher qui permettra le chiffrement RC4
			Cipher cipher = Cipher.getInstance(ALGORITHME_RC4);
			// Initialisation avec la clé passée en paramètre
			cipher.init(Cipher.ENCRYPT_MODE, secretKey);
			// Chiffrement du message
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
	 * Déchiffrement du message codé (paramètre data) à partir de la clé qui a servie précédemment à chiffrer.
	 * 
	 * @param data Message chiffré
	 * @param cle Clé de chiffrement/déchiffrement
	 * @return
	 */
	public String dechiffrer(byte[] data, String cle) {
		
		SecretKey secretKey = null;
		byte[] messageClair = null;
		String message = "";
		
		try {
			// Obtention d'un objet SecretKey qui contient la clé pour déchiffrer le message. 
			secretKey = new SecretKeySpec(cle.getBytes(), ALGORITHME_RC4);
			
			// Récupère une instance de Cipher qui permettra le déchiffrement RC4
			Cipher cipher = Cipher.getInstance(ALGORITHME_RC4);
			// Initialisation avec la clé passée en paramètre
			cipher.init(Cipher.DECRYPT_MODE, secretKey);
			// Déchiffrement du message
			messageClair = cipher.doFinal(data);
			// Convertion tableau de bytes en String
			message = new String(messageClair, "UTF-8"); // for UTF-8 encoding
			
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
