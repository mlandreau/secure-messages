package com.open.se.confidentialite;

import java.io.FileInputStream;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.security.PrivateKey;
import java.security.PublicKey;

import com.open.se.confidentialite.asym.RSA;
import com.open.se.confidentialite.sym.AES;
import com.open.se.confidentialite.sym.RC4;
import com.open.se.helpers.ConversionHelper;

public class Confidentialite {
	
	private static String projectPath = "";
	
	public static void main(String[] args) {
		projectPath = args[0];
		
		// Algorithme RC4
		testRC4();
		
		// Algorithme AES
		testAES();
		
		// Algorithme RSA
		testRSA();
	}
	
	/**
	 * Algorithme RC4
	 * 
	 * NOTE : algorithme peu sûr. Utiliser AES à la place.
	 */
	private static void testRC4() {
		
		// Instanciation de la classe qui fournira le service
		RC4 algorithmeRC4 = new RC4();
		// Message à chiffrer :
		String message = "Voici mon message secret";
		// Clé de chiffrement. Comme il s'agit d'un chiffrement symétrique, elle
		// est identique pour le chiffrement et le déchiffrement
		String cle = "B71822FA122A3EA5";

		// Appel de la méthode de chiffrement
		byte[] messageChiffre = algorithmeRC4.chiffrer(message, cle);
		System.out.println("------------------------------------------------------------------------------");
		System.out.println("   Algorithme : RC4");
		System.out.println("   Message en clair : '" + message + "'");
		System.out.println("   Message crypté : " + ConversionHelper.bytesToString(messageChiffre));

		// Appel de la méthode de déchiffrement avec la même clé que pour le chiffrement
		String messageClair = algorithmeRC4.dechiffrer(messageChiffre, cle);
		System.out.println("   Message décrypté : '" + messageClair + "'");
		System.out.println("------------------------------------------------------------------------------\n\n");
	}
	
	/**
	 * Algorithme AES
	 */
	private static void testAES() {
		
		// Instanciation de la classe qui fournira le service
		AES algorithmeAES = new AES();
		// Message à chiffrer :
		String message = "Voici mon message secret";
		
		// Clé de chiffrement. Comme il s'agit d'un chiffrement symétrique, elle
		// est identique pour le chiffrement et le déchiffrement
		// NOTE : jusqu'à java 8, la longueur de la clé est limitée à 128 bits. Pour une longueur de clé
		// plus élevée, ajouter une implémentation JCE externe.
		String cle = "B71822FA122A3EA5";

		// Appel de la méthode de chiffrement
		byte[] messageChiffre = algorithmeAES.chiffrer(message, cle);
		System.out.println("------------------------------------------------------------------------------");
		System.out.println("   Algorithme : AES");
		System.out.println("   Message en clair : '" + message + "'");
		System.out.println("   Message crypté : " + ConversionHelper.bytesToString(messageChiffre));

		// Appel de la méthode de déchiffrement avec la même clé que pour le chiffrement
		String messageClair = algorithmeAES.dechiffrer(messageChiffre, cle);
		System.out.println("   Message décrypté : '" + messageClair + "'");
		System.out.println("------------------------------------------------------------------------------\n\n");
	}

	/**
	 * Algorithme RSA
	 */
	private static void testRSA() {
		ObjectInputStream inputStream = null;
		
		try {
			// Instanciation de la classe qui fournira le service
			RSA algorithmeRSA = new RSA(projectPath);
			// Message à chiffrer :
			String message = "Voici mon message secret";
	
			// Génération des clé publique et privée après vérification qu'elles
			// n'ont pas déjà été générées.
			if (!algorithmeRSA.areKeysPresent()) {
				algorithmeRSA.genererCles();
			}
			
			// Chiffrement du message à partir de la clé publique
			inputStream = new ObjectInputStream(new FileInputStream(algorithmeRSA.getPublicKeyFile()));
			final PublicKey publicKey = (PublicKey) inputStream.readObject();
			final byte[] messageChiffre = algorithmeRSA.chiffrer(message, publicKey);
			inputStream.close();
		      
			// Appel de la méthode de chiffrement
			System.out.println("------------------------------------------------------------------------------");
			System.out.println("   Algorithme : RSA");
			System.out.println("   Message en clair : '" + message + "'");
			System.out.println("   Message crypté : " + ConversionHelper.bytesToString(messageChiffre));
	
			// Appel de la méthode de déchiffrement avec la même clé que pour le chiffrement
			inputStream = new ObjectInputStream(new FileInputStream(algorithmeRSA.getPrivateKeyFile()));
			final PrivateKey privateKey = (PrivateKey) inputStream.readObject();
			final String messageClair = algorithmeRSA.dechiffrer(messageChiffre, privateKey);
			inputStream.close(); 
			
			System.out.println("   Message décrypté : '" + messageClair + "'");
			System.out.println("------------------------------------------------------------------------------\n\n");
			
		} catch (IOException e) {
			e.printStackTrace();
		} catch (ClassNotFoundException e) {
			e.printStackTrace();
		}
	}
}
