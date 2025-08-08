# PV2 File Format Specification

## File Structure
```
[FILE_HEADER][IV_KEY][IV_HASH][PASSWORD_CHECK][ENCRYPTED_DATA][DATA_HASH][EOF_MARKER]
```

## Section Details

### 1. FILE_HEADER (3 bytes)
- Magic bytes: `PV2`
- Identifies file format

### 2. IV_KEY (16 bytes)
- AES initialization vector
- Optional (may be stored in separate `.ivkey` file)

### 3. IV_HASH (32 bytes)
- SHA-256 hash of IV_KEY
- Used for integrity verification

### 4. PASSWORD_CHECK (8 bytes)
- Encrypted known plaintext (`EPV2FILE`)
- Used for password verification

### 5. ENCRYPTED_DATA (variable)
- Data encrypted using AES-256 in EAX mode
- Block size determined by available system RAM

### 6. DATA_HASH (32 bytes)
- SHA-256 hash of encrypted data
- Used for integrity verification

### 7. EOF_MARKER (3 bytes)
- End-of-file marker: `EOF`

## Companion Files

### IV Key Files (`.ivkey`)
- 16-byte IV when using separate storage
- Named as `[original]_N.ivkey`

### Recovery Key Files (`.rkey`)
- SHA-256 hash of password in hex format
- Named as `[original]_N.rkey`

## Validation Process
1. Verify FILE_HEADER
2. Check IV_HASH matches computed IV
3. Verify PASSWORD_CHECK decrypts correctly
4. Validate DATA_HASH before decryption
5. Confirm EOF_MARKER exists

## Example Hex View
```
00000000: 50 56 32 00 01 23 45 67 89 AB CD EF 01 23 45 67  PV2..#Eg.....#Eg
00000010: 89 AB CD EF A1 B2 C3 D4 E5 F6 01 23 45 67 89 AB  ...........#Eg..
00000020: CD EF 01 23 45 67 89 AB CD EF 01 23 45 67 89 AB  ...#Eg.....#Eg..
00000030: CD EF 01 23 45 67 89 AB CD EF 01 23 45 67 89 AB  ...#Eg.....#Eg..
00000040: [Encrypted Data Block]                           [Binary]
0000XXXX: [SHA-256 Hash]                                   [Hash]
0000YYYY: EOF                                              EOF
```

