# Azure Key Vault Emulator

This module emulates the high-level behavior of **Azure Key Vault** used for securely managing cryptographic keys.  
Azure Key Vault typically uses **RSA-OAEP key wrapping** to protect Data Encryption Keys (DEKs) with a master Key Encryption Key (KEK) stored inside the vault.

This implementation uses classes defined in the `HSM` folder for low-level cryptographic operations.

---

## Components

### **AzureHSM**

This class is derived from the **BaseCryptoProcessor** class in the `HSM` module.  
It exposes APIs to:

- Generate **Data Encryption Keys (DEKs)** and register them in a simulated Key Vault.
- Create asymmetric or symmetric key pairs (AES, RSA, or EC).
- Wrap DEKs using the vault’s **master key (KEK)** with the **RSA-OAEP** wrapping algorithm.
- Retrieve, unwrap, or manage stored keys when required.

It also maintains internal maps to associate users with their respective keys, enabling fine-grained **access control**.  
Permissions can be granted to allow other users to utilize specific keys.

---

### **Azure_Server**

This component exposes the functionalities of `AzureHSM` through a **secure SSL socket interface** that accepts and responds with **JSON** commands.

It also implements **disk encryption and decryption** functionalities, simulating how Azure encrypts virtual machine disks.

The encryption is performed using a helper class:

```cpp
class DiskEncryptor
{
public:
    // Format a disk with LUKS (destructive)
    static int encryptVolume(const std::string& device, const std::vector<uint8_t>& dek)
    {
        return callCryptsetup("sudo cryptsetup luksFormat", device, dek);
    }

    // Unlock (decrypt) LUKS volume
    static int openVolume(const std::string& device, const std::string& mappingName, const std::vector<uint8_t>& dek)
    {
        return callCryptsetup("sudo cryptsetup luksOpen", device + " " + mappingName, dek);
    }

    // Lock (close) LUKS volume
    static int closeVolume(const std::string& mappingName)
    {
        return system(("sudo cryptsetup luksClose " + mappingName).c_str());
    }
};
````

#### **About DM-Crypt and LUKS**

**DM-Crypt** is a Linux kernel subsystem that provides transparent disk encryption using the device-mapper framework.
**LUKS (Linux Unified Key Setup)** is the standard format for managing encrypted block devices. It stores metadata, supports multiple passphrases, and uses symmetric ciphers (like AES) to secure partitions or entire disks efficiently.

---

### **Azure_Client**

This is a demonstration client that connects to the `Azure_Server` using a **secure TLS connection**.
It performs the following operations:

1. Generates a new DEK through the server.
2. Encrypts a virtual (imaginary) disk using the DEK.
3. Opens (decrypts) the encrypted volume on demand.
4. Closes and releases the volume securely.

This client serves as an example of how applications interact with the simulated Azure Key Vault service.

---

## Build Instructions

The project includes a `Makefile` and `envgen` script.


## Key Features

* Emulates **Azure Key Vault** behavior locally.
* Supports **RSA-OAEP key wrapping** and DEK generation.
* Simulates **disk encryption using LUKS/DM-Crypt**.
* Provides **secure JSON-based communication** over SSL.
* Implements **access control and key management** per user.


## 🧩 Creating and Managing a Virtual Disk Using `/dev/loop`

This section describes how to create a virtual block device using Linux loopback (`/dev/loopX`) devices.
Loop devices allow you to use a regular file as a virtual disk — useful for testing filesystems, disk encryption, or HSM emulation without touching real hardware.

---

### ⚙️ 1. Create a Virtual Disk Image

Create a blank image file that will act as the virtual disk:

```bash
sudo dd if=/dev/zero of=disk.img bs=1M count=100
```

* `if=/dev/zero` → source of zeroed bytes
* `of=disk.img` → output image file
* `bs=1M count=100` → creates a 100 MB file (adjust as needed)

---

### 🧲 2. Attach the Image to a Loop Device

Instead of manually choosing `/dev/loop0`, let the system assign a free loop device automatically:

```bash
sudo losetup -fP disk.img
```

This command:

* Finds the first available loop device
* Attaches `disk.img` to it
* Scans for partitions (via `-P`)

To verify the mapping:

```bash
sudo losetup -a
```

---

### 🧱 3. Format the Virtual Disk

Once attached, format it with your desired filesystem (for example, `ext4`):

```bash
sudo mkfs.ext4 /dev/loopX
```

*(Replace `loopX` with the actual loop device name, such as `loop0` or `loop1`.)*

---

### 📂 4. Mount the Virtual Disk

Mount the newly formatted device to access it as a normal filesystem:

```bash
sudo mkdir /mnt/loopdisk
sudo mount /dev/loopX /mnt/loopdisk
```

You can now read/write files under `/mnt/loopdisk` just like any other mounted drive.

---

### 🔍 5. Check the Status of Loop Devices

To see all active loop devices and their backing files:

```bash
sudo losetup -a
```

To view mount points:

```bash
mount | grep loop
```

---

### 🧹 6. Unmount and Detach the Virtual Disk

When done, unmount and detach the loop device:

```bash
sudo umount /mnt/loopdisk
sudo losetup -d /dev/loopX
```

This frees up the loop device for future use.

