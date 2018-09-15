package com.ppu.fmc;

import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManager;
import javax.net.ssl.X509TrustManager;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.boot.CommandLineRunner;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.builder.SpringApplicationBuilder;
import org.springframework.scheduling.annotation.EnableScheduling;

import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;

@SpringBootApplication
@EnableScheduling
public class Local2ovoApplication implements CommandLineRunner {

	private static final Logger log = LoggerFactory.getLogger(Local2ovoApplication.class);
	public static final String POM_LOCATION = "/META-INF/maven/com.ppu.fmc/local2ovo/pom.properties";

	public static long eventIdIncrementer = 0; // diisi dgn timestamp wkt service up

	public static void main(String[] args) {
		new SpringApplicationBuilder(Local2ovoApplication.class).web(false).run(args);
	}

	public static void trustSelfSignedSSL() {
		try {
			SSLContext ctx = SSLContext.getInstance("TLS");
			X509TrustManager tm = new X509TrustManager() {

				public void checkClientTrusted(X509Certificate[] xcs, String string) throws CertificateException {
				}

				public void checkServerTrusted(X509Certificate[] xcs, String string) throws CertificateException {
				}

				public X509Certificate[] getAcceptedIssuers() {
					return null;
				}
			};
			ctx.init(null, new TrustManager[] { tm }, null);
			SSLContext.setDefault(ctx);
		} catch (Exception ex) {
			ex.printStackTrace();
		}
	}

	@Override
	public void run(String... args) throws Exception {
		eventIdIncrementer = System.currentTimeMillis();

		trustSelfSignedSSL();
		
		log.info("LOCAL to OVO ready");

	}

}
