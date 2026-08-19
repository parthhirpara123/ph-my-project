"""
Error Handling and Debugging Example
====================================

This script demonstrates common Python errors and how to fix them properly.
"""

# ============================================================================
# PROBLEM 1: ZeroDivisionError
# ============================================================================

def divide_numbers(a, b):
    """
    Safely divide two numbers with error handling
    
    Fixes the ZeroDivisionError by checking if divisor is zero
    """
    if b == 0:
        return "Error: Cannot divide by zero!"
    return a / b


# ============================================================================
# PROBLEM 2: NameError
# ============================================================================

# This variable is now declared before use
undeclared_variable = "This variable is now properly declared!"


# ============================================================================
# PROBLEM 3: TypeError
# ============================================================================

def safe_string_concatenation(text, number):
    """
    Safely concatenate string and number
    
    Fixes the TypeError by converting number to string first
    """
    return text + str(number)


# ============================================================================
# MAIN: Run and test all fixes
# ============================================================================

def main():
    print("="*70)
    print("PYTHON ERROR HANDLING AND DEBUGGING")
    print("="*70)
    
    # TEST 1: Division by zero (FIXED)
    print("\n✅ TEST 1: SAFE DIVISION")
    print("-"*70)
    print(f"divide_numbers(10, 2) = {divide_numbers(10, 2)}")
    print(f"divide_numbers(10, 0) = {divide_numbers(10, 0)}")
    print("✓ ZeroDivisionError is now handled gracefully!")
    
    # TEST 2: Undeclared variable (FIXED)
    print("\n✅ TEST 2: DECLARED VARIABLE")
    print("-"*70)
    print(f"undeclared_variable = '{undeclared_variable}'")
    print("✓ NameError is fixed - variable is declared!")
    
    # TEST 3: Type error (FIXED)
    print("\n✅ TEST 3: SAFE CONCATENATION")
    print("-"*70)
    result = safe_string_concatenation("Number: ", 5)
    print(f"Result: {result}")
    print("✓ TypeError is fixed - converted number to string!")
    
    # BONUS: Show the errors that WOULD occur without fixes
    print("\n" + "="*70)
    print("WHAT HAPPENS WITHOUT FIXES (Educational Only)")
    print("="*70)
    
    # Show error for division by zero
    print("\n❌ ERROR 1: ZeroDivisionError")
    print("-"*70)
    print("Code: a / b  (when b = 0)")
    print("Error: ZeroDivisionError: division by zero")
    print("Fix: Check if b == 0 before dividing")
    
    # Show error for undeclared variable
    print("\n❌ ERROR 2: NameError")
    print("-"*70)
    print("Code: print(undeclared_variable)")
    print("Error: NameError: name 'undeclared_variable' is not defined")
    print("Fix: Declare the variable before using it")
    
    # Show error for type mismatch
    print("\n❌ ERROR 3: TypeError")
    print("-"*70)
    print("Code: 'Number: ' + 5")
    print("Error: TypeError: can only concatenate str (not 'int') to str")
    print("Fix: Convert number to string using str(5)")
    
    # BEST PRACTICES
    print("\n" + "="*70)
    print("PYTHON ERROR HANDLING BEST PRACTICES")
    print("="*70)
    print("""
1. USE TRY-EXCEPT FOR EXPECTED ERRORS
   ──────────────────────────────────
   try:
       result = divide_numbers(10, 0)
   except ValueError as e:
       print(f"Error: {e}")
   except ZeroDivisionError:
       print("Cannot divide by zero")

2. VALIDATE INPUT BEFORE USE
   ──────────────────────────
   def divide(a, b):
       if not isinstance(a, (int, float)):
           raise TypeError("a must be a number")
       if not isinstance(b, (int, float)):
           raise TypeError("b must be a number")
       if b == 0:
           raise ValueError("b cannot be zero")
       return a / b

3. USE MEANINGFUL ERROR MESSAGES
   ─────────────────────────────
   if b == 0:
       raise ValueError("Divisor cannot be zero")

4. DECLARE VARIABLES BEFORE USE
   ─────────────────────────────
   # Good
   result = None
   if condition:
       result = calculate()
   
   # Bad
   if condition:
       result = calculate()
   print(result)  # NameError if condition is False

5. USE TYPE CONVERSION WHEN NEEDED
   ────────────────────────────────
   # For string + number
   message = "Number: " + str(5)
   
   # Better: use f-strings
   message = f"Number: {5}"
   
   # Even better: use format()
   message = "Number: {}".format(5)

6. USE DEBUGGING TOOLS
   ───────────────────
   print(f"Variable type: {type(variable)}")
   print(f"Variable value: {variable}")
   print(f"Available attributes: {dir(object)}")

7. READ ERROR MESSAGES CAREFULLY
   ────────────────────────────
   Error messages tell you:
   • What type of error occurred
   • Where it occurred (line number)
   • What caused it (the problematic code)
   • Sometimes how to fix it

8. USE EXCEPTION HIERARCHY
   ──────────────────────
   try:
       # Code that might fail
       pass
   except (ValueError, TypeError) as e:
       # Handle multiple error types
       print(f"Invalid input: {e}")
   except Exception as e:
       # Catch all other errors
       print(f"Unexpected error: {e}")
   finally:
       # Always runs, even if error occurs
       print("Cleanup code here")
    """)
    
    print("="*70 + "\n")


if __name__ == "__main__":
    main()
