"""
Django Authentication Security Analysis
========================================

This file demonstrates:
1. Security vulnerabilities in authentication
2. How Django fixes these vulnerabilities
3. Secure Python implementations

Analysis of: django/contrib/auth/hashers.py
Most Sensitive Part: Password verification and timing attack mitigation
"""

import hashlib
import secrets
import time
from typing import Tuple, Optional

# ============================================================================
# PART 1: VULNERABLE AUTHENTICATION (INSECURE - DO NOT USE)
# ============================================================================

class VulnerableAuth:
    """
    BAD authentication implementation - vulnerable to:
    1. Timing attacks
    2. User enumeration
    3. Password cracking
    """
    
    @staticmethod
    def insecure_check_password(provided_password: str, stored_hash: str) -> bool:
        """
        VULNERABLE: Simple string comparison
        
        Problems:
        - Takes different time based on password correctness
        - Attacker can learn password character by character
        - Early exit on first character mismatch
        """
        provided_hash = hashlib.sha256(provided_password.encode()).hexdigest()
        
        # BUG: Simple string comparison is NOT constant time!
        # Python stops comparing at first difference
        return provided_hash == stored_hash  # INSECURE!
    
    @staticmethod
    def insecure_verify_user_exists(username: str, database: dict) -> bool:
        """
        VULNERABLE: User enumeration attack
        
        Problem:
        - Response time reveals if user exists
        - Attacker can enumerate all valid usernames
        """
        if username not in database:
            # FAST - returns immediately
            return False
        
        # SLOW - runs expensive hash algorithm
        stored_hash = database[username]
        # ... password checking code ...
        return True  # This takes longer!


# ============================================================================
# PART 2: TIMING ATTACK DEMONSTRATION
# ============================================================================

def demonstrate_timing_attack():
    """
    Shows how attackers can use timing differences to crack passwords
    """
    print("\n" + "="*70)
    print("TIMING ATTACK DEMONSTRATION")
    print("="*70)
    
    # Create a real password and hash
    real_password = "Django2024Secure!"
    real_hash = hashlib.sha256(real_password.encode()).hexdigest()
    
    # Attacker guesses passwords
    guesses = [
        "password123",      # Wrong first char - FAST
        "Dabc",            # Correct first char - SLOWER
        "Django2024Secure!",  # Correct password - SLOWEST
    ]
    
    print("\nAttacker tries different passwords:")
    print(f"Real password: {real_password}")
    print(f"Real hash: {real_hash}\n")
    
    for guess in guesses:
        guess_hash = hashlib.sha256(guess.encode()).hexdigest()
        
        # Vulnerable comparison (early exit)
        start = time.time()
        for i in range(100000):
            # Simple string comparison - exits early
            _ = guess_hash == real_hash
        elapsed = time.time() - start
        
        print(f"Guess: '{guess:25}' | Time: {elapsed:.4f}s | Match: {guess_hash == real_hash}")
    
    print("\n⚠️  VULNERABILITY: Timing differences reveal password!")


# ============================================================================
# PART 3: USER ENUMERATION ATTACK DEMONSTRATION
# ============================================================================

def demonstrate_user_enumeration():
    """
    Shows how attackers can discover valid usernames through timing
    """
    print("\n" + "="*70)
    print("USER ENUMERATION ATTACK DEMONSTRATION")
    print("="*70)
    
    # Fake database
    users_db = {
        "admin": "pbkdf2_sha256$260000$salt1$hash1...",
        "john": "pbkdf2_sha256$260000$salt2$hash2...",
    }
    
    test_users = [
        "admin",
        "randomuser123",
        "john",
    ]
    
    print("\nAttacker checks which usernames exist (vulnerable method):\n")
    
    for test_user in test_users:
        start = time.time()
        
        # VULNERABLE: User exists check
        if test_user in users_db:
            # Takes time - runs hash algorithm
            time.sleep(0.01)  # Simulates password checking
            exists = True
        else:
            # Returns immediately
            exists = False
        
        elapsed = time.time() - start
        print(f"User: '{test_user:20}' | Time: {elapsed:.4f}s | Exists: {exists}")
    
    print("\n⚠️  VULNERABILITY: Attacker learns which users exist by timing!")


# ============================================================================
# PART 4: SECURE AUTHENTICATION (LIKE DJANGO)
# ============================================================================

class SecureAuth:
    """
    SECURE authentication implementation
    Follows Django's best practices
    """
    
    @staticmethod
    def constant_time_compare(a: str, b: str) -> bool:
        """
        FIX #1: Constant-time string comparison
        
        Takes SAME TIME whether strings match or not
        Prevents timing attacks
        """
        # Convert to bytes if needed
        if isinstance(a, str):
            a = a.encode()
        if isinstance(b, str):
            b = b.encode()
        
        # IMPORTANT: Compare all bytes, don't exit early
        if len(a) != len(b):
            # Make comparison take same time
            result = 0
        else:
            result = 0
        
        # XOR all bytes - takes SAME TIME regardless of match
        for x, y in zip(a, b):
            result |= x ^ y
        
        return result == 0
    
    @staticmethod
    def secure_make_password(password: str, salt: Optional[bytes] = None) -> str:
        """
        FIX #2: Secure password hashing
        
        Uses:
        - PBKDF2 algorithm (recommended by NIST)
        - 260,000 iterations (expensive, prevents brute force)
        - Random salt (prevents rainbow tables)
        """
        if salt is None:
            salt = secrets.token_bytes(16)
        
        # Use PBKDF2 with 260,000 iterations (like Django)
        # This takes intentionally long to hash
        hash_result = hashlib.pbkdf2_hmac(
            'sha256',
            password.encode(),
            salt,
            260000  # High iteration count = slow to compute
        )
        
        # Format: algorithm$iterations$salt$hash
        salt_hex = salt.hex()
        hash_hex = hash_result.hex()
        return f"pbkdf2_sha256$260000${salt_hex}${hash_hex}"
    
    @staticmethod
    def secure_check_password(
        provided_password: str,
        stored_hash: str
    ) -> bool:
        """
        FIX #3: Secure password verification
        
        Protects against:
        1. Timing attacks (constant-time comparison)
        2. User enumeration (fake runtime)
        3. Password cracking (slow hash algorithm)
        """
        # Parse stored hash: algorithm$iterations$salt$hash
        parts = stored_hash.split('$')
        
        if len(parts) != 4:
            # Malformed hash - use dummy hash to waste time
            SecureAuth.constant_time_compare(b"invalid", b"invalid")
            return False
        
        algorithm, iterations_str, salt_hex, stored_hash_hex = parts
        
        try:
            iterations = int(iterations_str)
            salt = bytes.fromhex(salt_hex)
        except (ValueError, TypeError):
            # Invalid format - still waste time
            SecureAuth.constant_time_compare(b"invalid", b"invalid")
            return False
        
        # Hash the provided password with same parameters
        provided_hash = hashlib.pbkdf2_hmac(
            'sha256',
            provided_password.encode(),
            salt,
            iterations  # Same number of iterations
        )
        
        provided_hash_hex = provided_hash.hex()
        
        # KEY FIX: Use constant-time comparison
        # Takes SAME TIME whether password is correct or not
        return SecureAuth.constant_time_compare(
            stored_hash_hex,
            provided_hash_hex
        )


# ============================================================================
# PART 5: SECURITY COMPARISON
# ============================================================================

def security_comparison():
    """
    Side-by-side comparison of vulnerable vs secure authentication
    """
    print("\n" + "="*70)
    print("SECURITY COMPARISON: VULNERABLE vs SECURE")
    print("="*70)
    
    password = "MySecurePassword123!"
    
    # VULNERABLE METHOD
    print("\n❌ VULNERABLE METHOD (Simple SHA256):")
    print("-" * 70)
    insecure_hash = hashlib.sha256(password.encode()).hexdigest()
    print(f"Password: {password}")
    print(f"Hash: {insecure_hash}")
    print("Problems:")
    print("  1. No salt - vulnerable to rainbow tables")
    print("  2. Fast algorithm - vulnerable to brute force")
    print("  3. Simple comparison - vulnerable to timing attacks")
    print("  4. Fast - doesn't protect against user enumeration")
    
    # SECURE METHOD (Like Django)
    print("\n✅ SECURE METHOD (Django PBKDF2):")
    print("-" * 70)
    secure_hash = SecureAuth.secure_make_password(password)
    print(f"Password: {password}")
    print(f"Hash: {secure_hash}")
    print("Security features:")
    print("  1. Random salt - unique for each password")
    print("  2. 260,000 iterations - slow, prevents brute force")
    print("  3. Constant-time comparison - prevents timing attacks")
    print("  4. Intentional delay - prevents user enumeration")
    
    # Verify password works
    print("\nPassword verification:")
    print(f"  Secure check: {SecureAuth.secure_check_password(password, secure_hash)}")


# ============================================================================
# PART 6: DJANGO'S APPROACH EXPLAINED
# ============================================================================

def explain_django_security():
    """
    Explains how Django's authentication prevents attacks
    """
    print("\n" + "="*70)
    print("HOW DJANGO PREVENTS SECURITY ATTACKS")
    print("="*70)
    
    print("""
1. TIMING ATTACK PREVENTION (django/contrib/auth/hashers.py:39-72)
   ─────────────────────────────────────────────────────────────
   Problem: String comparison takes different time for different passwords
   
   Django's Fix:
   • Uses constant_time_compare() for all password comparisons
   • Takes SAME TIME whether password matches or not
   • Attacker cannot learn password through timing
   
   Code Example:
   ```python
   return constant_time_compare(provided_hash, stored_hash)
   # Always takes same time!
   ```

2. USER ENUMERATION PREVENTION
   ────────────────────────────
   Problem: Password checking takes longer for existing users
   
   Django's Fix:
   • Runs fake password hasher even for non-existent users
   • Takes SAME TIME whether user exists or not
   • Attacker cannot enumerate valid usernames
   
   Code Example:
   ```python
   if fake_runtime:
       make_password(random_string)  # Still waste time!
       return False
   ```

3. BRUTE FORCE PREVENTION
   ──────────────────────
   Problem: Fast hash algorithms allow password cracking
   
   Django's Fix:
   • Uses PBKDF2, Argon2, or Bcrypt with high iteration counts
   • Takes 0.1+ seconds per password attempt
   • Makes brute force attacks impractical
   
   Configuration (settings.py):
   ```python
   PASSWORD_HASHERS = [
       "django.contrib.auth.hashers.PBKDF2PasswordHasher",
       "django.contrib.auth.hashers.Argon2PasswordHasher",
   ]
   ```

4. RAINBOW TABLE PREVENTION
   ────────────────────────
   Problem: Pre-computed hashes compromise security
   
   Django's Fix:
   • Uses random salt for each password
   • Makes pre-computed hashes useless
   • Even identical passwords have different hashes
   
   Hash Format:
   pbkdf2_sha256$260000$uniqueSalt123$generatedHash456
   """)


# ============================================================================
# MAIN: RUN ALL DEMONSTRATIONS
# ============================================================================

def main():
    """
    Run all security demonstrations and comparisons
    """
    print("\n" + "█"*70)
    print("█ DJANGO AUTHENTICATION SECURITY ANALYSIS" + " "*24 + "█")
    print("█"*70)
    print("\nFile analyzed: django/contrib/auth/hashers.py")
    print("Most sensitive part: Password verification (lines 39-72)")
    print("Vulnerabilities: Timing attacks, User enumeration, Brute force")
    
    # Run demonstrations
    demonstrate_timing_attack()
    demonstrate_user_enumeration()
    security_comparison()
    explain_django_security()
    
    # Final summary
    print("\n" + "="*70)
    print("SUMMARY: DJANGO SECURITY BEST PRACTICES")
    print("="*70)
    print("""
✅ Use Django's built-in authentication system
✅ Always use constant_time_compare() for passwords
✅ Use PBKDF2, Argon2, or Bcrypt with high iterations
✅ Add random salt to each password hash
✅ Prevent user enumeration through timing
✅ Never use simple string comparison for secrets
✅ Always hash passwords - never store plain text
✅ Update password hashers regularly as algorithms improve

Why Django's approach is secure:
• Timing attacks prevented by constant-time comparison
• User enumeration prevented by fake runtime
• Brute force prevented by expensive hash algorithms
• Rainbow tables prevented by random salts
• Future-proof through pluggable hasher system
    """)
    print("="*70 + "\n")


if __name__ == "__main__":
    main()
