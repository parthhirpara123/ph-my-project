# Simple Calculator in Python
# This file has basic math functions for addition, subtraction, multiplication, and division

def add(a, b):
    """
    Add two numbers together
    Example: add(5, 3) returns 8
    """
    return a + b


def subtract(a, b):
    """
    Subtract second number from first number
    Example: subtract(10, 4) returns 6
    """
    return a - b


def multiply(a, b):
    """
    Multiply two numbers together
    Example: multiply(4, 5) returns 20
    """
    return a * b


def divide(a, b):
    """
    Divide first number by second number
    Example: divide(20, 4) returns 5
    
    Note: Cannot divide by zero - will show error
    """
    if b == 0:
        return "Error: Cannot divide by zero!"
    return a / b


# Test the calculator functions
if __name__ == "__main__":
    print("=" * 40)
    print("SIMPLE CALCULATOR TEST")
    print("=" * 40)
    
    # Test Addition
    print("\n1. ADDITION TEST:")
    result = add(10, 5)
    print(f"   add(10, 5) = {result}")
    
    # Test Subtraction
    print("\n2. SUBTRACTION TEST:")
    result = subtract(10, 5)
    print(f"   subtract(10, 5) = {result}")
    
    # Test Multiplication
    print("\n3. MULTIPLICATION TEST:")
    result = multiply(10, 5)
    print(f"   multiply(10, 5) = {result}")
    
    # Test Division
    print("\n4. DIVISION TEST:")
    result = divide(10, 5)
    print(f"   divide(10, 5) = {result}")
    
    # Test Division by Zero
    print("\n5. DIVISION BY ZERO TEST:")
    result = divide(10, 0)
    print(f"   divide(10, 0) = {result}")
    
    print("\n" + "=" * 40)
    print("ALL TESTS COMPLETED!")
    print("=" * 40)
