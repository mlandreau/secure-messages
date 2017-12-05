package com.open.se.integrite;

import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

public class Integrite {

	// Fonctions de hachage : MD5, SHA1
	private static final String DIGEST_METHOD_MD5 = "MD5";
	private static final String DIGEST_METHOD_SHA1 = "SHA1";
	private static final String DIGEST_METHOD_SHA256 = "SHA-256";
	private static final String DIGEST_METHOD_SHA512 = "SHA-512";
	
	public static void main(String[] args)  {
		
		// Fichier en entrée dont il faudra calculer l'empreinte
		String datafile = "files/loremipsum.txt";
		
		
	    System.out.println("Empreinte du fichier (MD5) : " + getEmpreinte(datafile, DIGEST_METHOD_MD5));
	    System.out.println("Empreinte du fichier (SHA1) : " + getEmpreinte(datafile, DIGEST_METHOD_SHA1));
	    System.out.println("Empreinte du fichier (SHA2 256) : " + getEmpreinte(datafile, DIGEST_METHOD_SHA256));
	    System.out.println("Empreinte du fichier (SHA2 512) : " + getEmpreinte(datafile, DIGEST_METHOD_SHA512));
	    
	}

	/**
	 * Calcul de l'empreinte du fichier passé en paramètre en fonction de la méthode de hachage voulue
	 * 
	 * @param datafile Fichier en entrée
	 * @param method Methode de hachage
	 * @return Empreinte calculée
	 */
	@SuppressWarnings("resource")
	private static String getEmpreinte(String datafile, String method){
		// Fichier en entrée dont il faudra calculer l'empreinte
		StringBuffer sb = new StringBuffer("");

		try {
			// Hachage
			MessageDigest md = MessageDigest.getInstance(method);

			// Lecture du fichier en entrée
			FileInputStream fis = new FileInputStream(datafile);
			byte[] dataBytes = new byte[1024];

			int nread = 0;

			while ((nread = fis.read(dataBytes)) != -1) {
				md.update(dataBytes, 0, nread);
			}
			;

			// Calcul de l'empreinte
			byte[] mdbytes = md.digest();

			// Convertion du tableau de bytes en hexa
			for (int i = 0; i < mdbytes.length; i++) {
				sb.append(Integer.toString((mdbytes[i] & 0xff) + 0x100, 16)
						.substring(1));
			}

		} catch (NoSuchAlgorithmException e) {
			e.printStackTrace();
		} catch (FileNotFoundException e) {
			e.printStackTrace();
		} catch (IOException e) {
			e.printStackTrace();
		}

		return sb.toString();
	}
}
