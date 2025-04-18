import json
import time
from itertools import product

def rabin_karp_hash(s, base, mod):
    n = len(s)
    h = [0] * (n + 1)
    power = [1] * (n + 1)
    for i in range(n):
        h[i + 1] = (h[i] * base + ord(s[i])) % mod
        power[i + 1] = (power[i] * base) % mod
    return h, power

def get_hash(h, power, l, r, mod):
    return (h[r] - h[l] * power[r - l]) % mod

def check(strs, length, base, mod):
    h0, power = rabin_karp_hash(strs[0], base, mod)
    substr_hashes = set(get_hash(h0, power, i, i + length, mod) for i in range(len(strs[0]) - length + 1))

    for s in strs[1:]:
        h, _ = rabin_karp_hash(s, base, mod)
        current_hashes = set(get_hash(h, power, i, i + length, mod) for i in range(len(s) - length + 1))
        substr_hashes &= current_hashes
        if not substr_hashes:
            return None

    h0_map = {get_hash(h0, power, i, i + length, mod): strs[0][i:i + length] for i in range(len(strs[0]) - length + 1)}
    for h in substr_hashes:
        return h0_map[h]
    return None

def longest_common_substring(strs, min_length=5):
    if not strs:
        return None
    
    base = 257
    mod = 10 ** 9 + 7
    low, high = min_length, min(len(s) for s in strs)
    result = None

    while low <= high:
        mid = (low + high) // 2
        substr = check(strs, mid, base, mod)
        if substr and len(substr) >= min_length:
            result = substr
            low = mid + 1
        else:
            high = mid - 1
            
    return result

# def combination(arr):
#     if not arr:
#         print([[]])
    
#     result = []
    
#     for combo in product(*arr):
#         lcs = longest_common_substring(list(combo), min_length=5)
#         if lcs != None:
#             result.append(lcs)
    
#     with open("./output_lcs/LCS3_AgentTesla.json", "w") as f:
# 	    json.dump(result, f)

def combination(arr, time_limit_minutes=30):
    if not arr:
        print([[]])
        return

    start_time = time.time()
    time_limit_seconds = time_limit_minutes * 60
    result = []

    total_combinations = 1
    for group in arr:
        total_combinations *= len(group)

    print(f"Total combinations to process: {total_combinations}")

    for i, combo in enumerate(product(*arr)):
        # Cek batas waktu
        elapsed_time = time.time() - start_time
        if elapsed_time > time_limit_seconds:
            print(f"⏱️ Stopped early after {elapsed_time:.2f} seconds ({i} combinations processed)")
            break

        lcs = longest_common_substring(list(combo), min_length=5)
        if lcs is not None and lcs not in result:
            result.append(lcs)

        if i % 1000 == 0:
            print(f"Processed {i}/{total_combinations} combinations...")

    # Simpan hasil
    with open("./output_lcs/LCS3_AgentTesla.json", "w") as f:
        json.dump(result, f, indent=4, sort_keys=True)

    print(f"✅ Done. {len(result)} LCS entries saved.")

def main ():
    # Load data
    with open('./output_parser/String2_AgentTesla.json', 'r') as f:
        json_data = json.load(f)
    
    array_of_string = []

    for file_data in json_data.values():
        ascii_strings = file_data[".text"]["ascii"]
        array_of_string.append(ascii_strings)
    
    combination(array_of_string)

if __name__ == "__main__":
    main()