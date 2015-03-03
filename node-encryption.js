var crypto = require("crypto");

// ----- Decrypts a string coming from the go encrytion method
exports.decrypt = function(content, key) {
	// Split the string on the "$" sign as that will allow us to get at the IV which was passed in with the encrypted string.
	var contentParts = content.split("$");

	if (contentParts.length >= 2) {
		// Create the cipher for decrypting the passed in string. We use the IV that was passed in and would have been encoded to hex. 
		// We therefore need get the IV back into the string used by the encryption
		var decipher = crypto.createDecipheriv("aes-256-cbc", key.toString("binary"), new Buffer(contentParts[1], "hex").toString())

		// Decrypt the string passed in
		var decrypted = decipher.update(contentParts[0], 'hex', 'utf8')
		decrypted += decipher.final('utf8');

		// return the now decrypted string
		return decrypted;
	}
	else return ""
}
	
// ----- Encypts a string into an AES format compatible with node
exports.encrypt = function(content, key) {
	// Create a random IV string to be used by the encryption
	function createIV() {
		var s4 = function () {
		  	return Math.floor((1 + Math.random()) * 0x10000).toString(16).substring(1);
		};

		return s4() + s4() + s4() + s4();
	}

	// Create a new IV for the encryption. This doesnt need to be secured but should be unique for every encryption
	var iv = createIV();

    cipher = crypto.createCipheriv("aes-256-cbc", key.toString("binary"), iv);

    cipher.setEncoding('hex');
    cipher.write(content);
    cipher.end();

    cipher_text = cipher.read();

    return cipher_text + "$" + iv.toString('hex');
}