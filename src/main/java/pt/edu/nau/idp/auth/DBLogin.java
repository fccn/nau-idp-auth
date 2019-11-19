package pt.edu.nau.idp.auth;

import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.util.Arrays;
import java.util.Base64;
import java.util.List;
import java.util.Map;

import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import javax.security.auth.Subject;
import javax.security.auth.callback.Callback;
import javax.security.auth.callback.CallbackHandler;
import javax.security.auth.callback.NameCallback;
import javax.security.auth.callback.PasswordCallback;
import javax.security.auth.callback.UnsupportedCallbackException;
import javax.security.auth.login.FailedLoginException;
import javax.security.auth.login.LoginException;
import javax.security.auth.spi.LoginModule;

public class DBLogin implements LoginModule {

	// initial state
	protected Subject subject;
	protected CallbackHandler callbackHandler;
	protected Map<String, ?> sharedState;
	protected Map<String, ?> options;

	// configurable option
	protected boolean debug = false;

	// the authentication status
	protected boolean commitSucceeded = false;

	protected String dbDriver;
	protected String dbURL;
	protected String dbUser;
	protected String dbPassword;
	protected String dbQuery;
	// select password from aut_user where username = ?;

	// select * from (select substring_index(password, '$', 1) as alg,
	// substring_index(substring_index(password, '$', 2), '$', -1) as iter,
	// substring_index(password, '$', -1) as hash from auth_user) as t where t.alg =
	// 'pbkdf2_sha256' and username = ?;

	@Override
	public void initialize(Subject subject, CallbackHandler callbackHandler, Map<String, ?> sharedState,
			Map<String, ?> options) {
		this.callbackHandler = callbackHandler;

		dbDriver = getOption("dbDriver", null);
		if (dbDriver == null)
			throw new Error("No database driver named (dbDriver=?)");
		dbURL = getOption("dbURL", null);
		if (dbURL == null)
			throw new Error("No database URL specified (dbURL=?)");
		dbUser = getOption("dbUser", null);
		dbPassword = getOption("dbPassword", null);
		if ((dbUser == null && dbPassword != null) || (dbUser != null && dbPassword == null))
			throw new Error("Either provide dbUser and dbPassword or encode both in dbURL");

		// get options like:

		// Object tmp = options.get("principalsQuery");
	}

	@Override
	public boolean login() throws LoginException {

		// username and password
		String username;
		char password[] = null;

		try {
			// prompt for a username and password
			if (callbackHandler == null)
				throw new LoginException(
						"Error: no CallbackHandler available to garner authentication information from the user");

			Callback[] callbacks = new Callback[2];
			callbacks[0] = new NameCallback("Username: ");
			callbacks[1] = new PasswordCallback("Password: ", false);

			try {
				callbackHandler.handle(callbacks);

				// Get username...
				username = ((NameCallback) callbacks[0]).getName();

				// ...password...
				password = ((PasswordCallback) callbacks[1]).getPassword();
				((PasswordCallback) callbacks[1]).clearPassword();
			} catch (java.io.IOException ioe) {
				throw new LoginException(ioe.toString());
			} catch (UnsupportedCallbackException uce) {
				throw new LoginException("Error: " + uce.getCallback().toString()
						+ " not available to garner authentication information from the user");
			}

			// Attempt to logon using the supplied credentials
			validateUser(username, password); // may throw
		} finally {
			smudge(password);
		}

		return true;
	}

	protected synchronized boolean validateUser(String username, char password[]) throws LoginException {
		ResultSet rsu = null, rsr = null;
		Connection con = null;
		PreparedStatement psu = null;

		try {
			Class.forName(dbDriver);
			if (dbUser != null)
				con = DriverManager.getConnection(dbURL, dbUser, dbPassword);
			else
				con = DriverManager.getConnection(dbURL);

			psu = con.prepareStatement(dbQuery);

			psu.setString(1, username);

			rsu = psu.executeQuery();
			if (!rsu.next())
				throw new FailedLoginException("Unknown user");

			String passwordDB = rsu.getString(1);

			List<String> passwordDBArray = Arrays.asList(passwordDB.split("\\$"));
			String algorithm = passwordDBArray.get(0);

			if (!algorithm.equals("pbkdf2_sha256")) {
				throw new LoginException("Error algorithm doesn't match");
			}

			int iterations = Integer.valueOf(passwordDBArray.get(1));
			byte[] salt = passwordDBArray.get(2).getBytes();
			String passwordHashedOnDB = passwordDBArray.get(3);

			byte[] encryptedPassword = getEncryptedPassword(password, salt, iterations, 32);
			String encryptedPasswordAsString = Base64.getEncoder().encodeToString(encryptedPassword);

			if (!passwordHashedOnDB.equals(encryptedPasswordAsString)) {
				throw new FailedLoginException("Bad password");
			}
			return true;
		} catch (ClassNotFoundException e) {
			throw new LoginException("Error reading user database (" + e.getMessage() + ")");
		} catch (SQLException e) {
			throw new LoginException("Error reading user database (" + e.getMessage() + ")");
		} catch (NoSuchAlgorithmException e) {
			e.printStackTrace();
			throw new LoginException("Error no such algorithm exception (" + e.getMessage() + ")");
		} catch (InvalidKeySpecException e) {
			e.printStackTrace();
			throw new LoginException("Error invalid key spec (" + e.getMessage() + ")");
		} finally {
			try {
				if (rsu != null)
					rsu.close();
				if (rsr != null)
					rsr.close();
				if (psu != null)
					psu.close();
				if (con != null)
					con.close();
			} catch (Exception e) {
			}
		}
	}

	@Override
	public boolean commit() throws LoginException {
		return true;
	}

	@Override
	public boolean abort() throws LoginException {
		return true;
	}

	@Override
	public boolean logout() throws LoginException {
		return true;
	}

	/**
	 * Get a String option from the module's options.
	 *
	 * @param name Name of the option
	 * @param dflt Default value for the option
	 * @return The String value of the options object.
	 */
	protected String getOption(String name, String dflt) {
		String opt = (String) options.get(name);
		return opt == null ? dflt : opt;
	}

	public static void smudge(char pwd[]) {
		if (null != pwd) {
			for (int b = 0; b < pwd.length; b++) {
				pwd[b] = 0;
			}
		}
	}

	public static byte[] getEncryptedPassword(char[] password, byte[] salt, int iterations, int derivedKeyLength)
			throws NoSuchAlgorithmException, InvalidKeySpecException {
		KeySpec spec = new PBEKeySpec(password, salt, iterations, derivedKeyLength * 8);

		SecretKeyFactory f = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");

		return f.generateSecret(spec).getEncoded();
	}

}

