package com.open.se.certificat.keystore;

import java.io.FileInputStream;
import java.io.IOException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;

/**
 * Classe proposant des méthodes de manipulation d'un magasin de certificats
 * 
 * @author Mlandreau
 *
 */
public class UsingKeystore {

	// Type de magasin de certificats
	private static final String KEYSTORE_TYPE = "JKS";
	// Accès au keystore
	private static final String KEYSTORE_FILENAME = "C:/Program Files/Java/jre1.8.0_144/bin/monKeystore.jks";
	// Mot de passe du magasin de certificats
	private static final String KEYSTORE_PWD = "open44";

	
	public static void main(String[] args) {
		
		Certificate certificat = getCerificat("monAlias");
		System.out.println(certificat);
	    
	}
	
	/**
	 * Récupère le certificat du keystore via l'alias placé en paramètre
	 * 
	 * @param alias Nom de l'alias sous lequel le certificat est enregistré
	 * @return Le certificat si trouvé
	 */
	private static Certificate getCerificat(String alias){
		Certificate certificat = null;
		
		try {
			// Chargement du magasin de certificats
	    	FileInputStream fIn = new FileInputStream(KEYSTORE_FILENAME);
		    KeyStore keystore = KeyStore.getInstance(KEYSTORE_TYPE);
			keystore.load(fIn, KEYSTORE_PWD.toCharArray());
			
			// Récupération du certificat à partir de son alias
			certificat = keystore.getCertificate(alias);
			
		} catch (NoSuchAlgorithmException | CertificateException | IOException | KeyStoreException e) {
			e.printStackTrace();
		}
		
		return certificat;
		
	}
}
