"""
Quick test script to verify all API endpoints are working
"""
import requests
import json
from datetime import datetime

BASE_URL = "http://localhost:8000"

def test_health():
    """Test health check endpoint"""
    print("🔍 Testing /health endpoint...")
    try:
        response = requests.get(f"{BASE_URL}/health")
        print(f"✅ Status: {response.status_code}")
        print(f"   Response: {response.json()}")
        return response.status_code == 200
    except Exception as e:
        print(f"❌ Error: {e}")
        return False

def test_homepage():
    """Test homepage loads"""
    print("\n🔍 Testing / (homepage)...")
    try:
        response = requests.get(f"{BASE_URL}/")
        print(f"✅ Status: {response.status_code}")
        print(f"   Content length: {len(response.text)} bytes")
        return response.status_code == 200
    except Exception as e:
        print(f"❌ Error: {e}")
        return False

def test_stats():
    """Test statistics endpoint"""
    print("\n🔍 Testing /stats endpoint...")
    try:
        response = requests.get(f"{BASE_URL}/stats")
        print(f"✅ Status: {response.status_code}")
        print(f"   Response: {response.json()}")
        return response.status_code == 200
    except Exception as e:
        print(f"❌ Error: {e}")
        return False

def test_scan():
    """Test URL scanning"""
    print("\n🔍 Testing /scan endpoint...")
    test_urls = [
        "https://google.com",
        "https://github.com",
        "https://example.com"
    ]
    
    for url in test_urls:
        try:
            print(f"   Scanning: {url}")
            response = requests.post(
                f"{BASE_URL}/scan",
                data={"url": url}
            )
            print(f"   ✅ Status: {response.status_code}")
            result = response.json()
            print(f"   Risk: {result.get('risk')}, "
                  f"Malicious: {result.get('malicious')}, "
                  f"Harmless: {result.get('harmless')}")
            if response.status_code != 200:
                return False
        except Exception as e:
            print(f"   ❌ Error: {e}")
            return False
    
    return True

def test_history():
    """Test scan history endpoint"""
    print("\n🔍 Testing /api/history endpoint...")
    try:
        response = requests.get(f"{BASE_URL}/api/history")
        print(f"✅ Status: {response.status_code}")
        history = response.json().get('history', [])
        print(f"   Found {len(history)} scan records")
        if history:
            print(f"   Latest scan: {history[0].get('url')}")
        return response.status_code == 200
    except Exception as e:
        print(f"❌ Error: {e}")
        return False

def main():
    """Run all tests"""
    print("=" * 60)
    print("PhishGuard AI - Endpoint Test Suite")
    print("=" * 60)
    print(f"Testing server at: {BASE_URL}")
    print(f"Time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print("=" * 60)
    
    tests = [
        ("Health Check", test_health),
        ("Homepage", test_homepage),
        ("Statistics", test_stats),
        ("URL Scanning", test_scan),
        ("Scan History", test_history)
    ]
    
    results = {}
    for name, test_func in tests:
        results[name] = test_func()
    
    print("\n" + "=" * 60)
    print("Test Results Summary")
    print("=" * 60)
    
    passed = sum(1 for v in results.values() if v)
    total = len(results)
    
    for name, result in results.items():
        status = "✅ PASS" if result else "❌ FAIL"
        print(f"{status} - {name}")
    
    print(f"\nTotal: {passed}/{total} tests passed")
    
    if passed == total:
        print("\n🎉 All tests passed! Server is fully operational.")
        print(f"\n🌐 Open your browser to: {BASE_URL}")
    else:
        print("\n⚠️ Some tests failed. Check server logs.")
    
    print("=" * 60)

if __name__ == "__main__":
    main()
