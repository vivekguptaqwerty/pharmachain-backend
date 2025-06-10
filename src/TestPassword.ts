import bcrypt from 'bcryptjs';

// Replace with the hash from your database
const storedHash = '$2b$10$b6CUP1W1u/P.ntgVvoi0P.QfRS3Ual1Lpv2tc97jzZ5QyWgAZ36u2'; // From the db.users.find query
const passwordToTest = 'anshika123'; // Replace with the password you're trying to log in with

bcrypt.compare(passwordToTest, storedHash, (err: Error | null, isMatch?: boolean) => {
  if (err) {
    console.error('Error comparing password:', err);
    return;
  }
  console.log('Password match:', isMatch === true);
});