package pt.edu.nau.idp.auth;

import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.util.Base64;
import java.util.Map;
import java.util.Optional;

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

/**
 * Permits a database login using Java JAAS.
 *
 * @author Ivo Branco <ivo.branco@fccn.pt>
 *
 */
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

	//
	// options
	//
	// required option
	protected String dbDriver;
	// required option
	protected String dbURL;
	protected String dbUser;
	protected String dbPassword;

	// required option
	protected String dbQuery;

	protected int passwordPosition;
	protected String fixedAlgorithm;
	protected int algorithmPosition;
	protected int saltPosition;
	protected int iterationCountPosition;
	protected int keyLengthPosition; // 32 * 8
	protected boolean encodePasswordBase64;

	// select password from aut_user where username = ?;

	// select * from (select substring_index(password, '$', 1) as alg,
	// substring_index(substring_index(password, '$', 2), '$', -1) as iter,
	// substring_index(password, '$', -1) as hash from auth_user) as t where t.alg =
	// 'pbkdf2_sha256' and username = ?;

	@Override
	public void initialize(Subject subject, CallbackHandler callbackHandler, Map<String, ?> sharedState,
			Map<String, ?> options) {
		this.subject = subject;
		this.callbackHandler = callbackHandler;
		this.sharedState = sharedState;
		this.options = options;

		dbDriver = getOption("dbDriver", null);
		if (dbDriver == null) {
			throw new Error("No database driver named (dbDriver=?)");
		}
		dbURL = getOption("dbURL", null);
		if (dbURL == null) {
			throw new Error("No database URL specified (dbURL=?)");
		}
		dbUser = getOption("dbUser", null);
		dbPassword = getOption("dbPassword", null);
		if ((dbUser == null && dbPassword != null) || (dbUser != null && dbPassword == null)) {
			throw new Error("Either provide dbUser and dbPassword or encode both in dbURL");
		}

		dbQuery = getOption("dbQuery", null);
		if (dbQuery == null) {
			throw new Error("No database query specified (dbQuery=?)");
		}

		passwordPosition = getOption("passwordPosition", 0);
		fixedAlgorithm = getOption("fixedAlgorithm", null);
		algorithmPosition = getOption("algorithmPosition", -1);
		if (fixedAlgorithm == null && algorithmPosition == -1) {
			throw new Error("Either provide fixedAlgorithm or algorithmPosition");
		}
		saltPosition = getOption("saltPosition", -1);
		iterationCountPosition = getOption("iterationCountPosition", -1);
		keyLengthPosition = getOption("keyLengthPosition", -1);
		encodePasswordBase64 = getOption("encodePasswordBase64", false);
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

			String passwordDB = rsu.getString(this.passwordPosition);
			String algorithm = this.algorithmPosition >= 0 ? rsu.getString(this.algorithmPosition)
					: this.fixedAlgorithm;

			byte[] salt = this.saltPosition >= 0 ? rsu.getBytes(this.saltPosition) : null;

			Integer iterationCount = this.iterationCountPosition >= 0 ? rsu.getInt(this.iterationCountPosition) : null;

			Integer keyLength = this.keyLengthPosition >= 0 ? rsu.getInt(this.keyLengthPosition) : null;

			byte[] encryptedPassword = getEncryptedPassword(password, algorithm, salt, iterationCount, keyLength);

			String encryptedPasswordAsString;
			if (this.encodePasswordBase64) {
				encryptedPasswordAsString = Base64.getEncoder().encodeToString(encryptedPassword);
			} else {
				encryptedPasswordAsString = new String(encryptedPassword);
			}

			if (!passwordDB.equals(encryptedPasswordAsString)) {
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
	 * Get an option from the module's options as String, Integer or Boolean. If
	 * default value is null return as String.
	 *
	 * @param name Name of the option
	 * @param dflt Default value for the option
	 * @return The value of the options object.
	 */
	protected <T> T getOption(String name, T dflt) {
		String opt = (String) this.options.get(name);
		return Optional.ofNullable(opt).map(o -> {
			if (dflt == null) {
				return o;
			} else if (String.class.isAssignableFrom(dflt.getClass())) {
				return o;
			} else if (Integer.class.isAssignableFrom(dflt.getClass())) {
				return Integer.valueOf(o);
			} else if (Boolean.class.isAssignableFrom(dflt.getClass())) {
				return Boolean.valueOf(o);
			}
			throw new IllegalArgumentException("Invalid argument " + name);
		}).map(o -> {
			return (T) o;
		}).orElse(dflt);
	}

	public static void smudge(char pwd[]) {
		if (null != pwd) {
			for (int b = 0; b < pwd.length; b++) {
				pwd[b] = 0;
			}
		}
	}

	public static byte[] getEncryptedPassword(char[] password, String algorithm, byte[] salt, Integer iterations,
			Integer derivedKeyLength) throws NoSuchAlgorithmException, InvalidKeySpecException {

		KeySpec spec;
		if (derivedKeyLength != null) {
			spec = new PBEKeySpec(password, salt, iterations, derivedKeyLength);
		} else if (iterations != null) {
			spec = new PBEKeySpec(password, salt, iterations);
		} else {
			spec = new PBEKeySpec(password);
		}

		SecretKeyFactory f = SecretKeyFactory.getInstance(algorithm);

		return f.generateSecret(spec).getEncoded();
	}

}
