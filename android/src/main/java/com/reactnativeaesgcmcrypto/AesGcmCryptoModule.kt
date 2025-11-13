package com.reactnativeaesgcmcrypto

import android.util.Log
import com.facebook.react.bridge.*
import com.facebook.react.module.annotations.ReactModule
import org.bouncycastle.jce.provider.BouncyCastleProvider
import java.io.File
import java.security.GeneralSecurityException
import java.security.Security
import java.util.*
import javax.crypto.Cipher
import javax.crypto.SecretKey
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.SecretKeySpec

class EncryptionOutput(val iv: ByteArray,
                       val tag: ByteArray,
                       val ciphertext: ByteArray)

@ReactModule(name = "AesGcmCrypto")
class AesGcmCryptoModule(reactContext: ReactApplicationContext) : ReactContextBaseJavaModule(reactContext) {
  val GCM_TAG_LENGTH = 16
  val BUFFER_SIZE = 8192

  init {
    if (Security.getProvider(BouncyCastleProvider.PROVIDER_NAME) == null) {
      Security.addProvider(BouncyCastleProvider())
    }
  }

  override fun getName(): String {
    return "AesGcmCrypto"
  }

  private fun getSecretKeyFromString(key: ByteArray): SecretKey {
    return SecretKeySpec(key, 0, key.size, "AES")
  }

  @Throws(javax.crypto.AEADBadTagException::class)
  fun decryptData(ciphertext: ByteArray, key: ByteArray, iv: String, tag: String): ByteArray {
    val secretKey: SecretKey = getSecretKeyFromString(key)
    val ivData = iv.hexStringToByteArray()
    val tagData = tag.hexStringToByteArray()
    val cipher = Cipher.getInstance("AES/GCM/NoPadding")
    val spec = GCMParameterSpec(GCM_TAG_LENGTH * 8, ivData)
    cipher.init(Cipher.DECRYPT_MODE, secretKey, spec)
    return cipher.doFinal(ciphertext + tagData)
  }

  fun encryptData(plainData: ByteArray, key: ByteArray): EncryptionOutput {
    val secretKey: SecretKey = getSecretKeyFromString(key)

    val cipher = Cipher.getInstance("AES/GCM/NoPadding")
    cipher.init(Cipher.ENCRYPT_MODE, secretKey)
    val iv = cipher.iv.copyOf()
    val result = cipher.doFinal(plainData)
    val ciphertext = result.copyOfRange(0, result.size - GCM_TAG_LENGTH)
    val tag = result.copyOfRange(result.size - GCM_TAG_LENGTH, result.size)
    return EncryptionOutput(iv, tag, ciphertext)
  }

  @ReactMethod
  fun decrypt(base64CipherText: String,
              key: String,
              iv: String,
              tag: String,
              isBinary: Boolean,
              promise: Promise) {
    try {
      val keyData = Base64.getDecoder().decode(key)
      val ciphertext: ByteArray = Base64.getDecoder().decode(base64CipherText)
      val unsealed: ByteArray = decryptData(ciphertext, keyData, iv, tag)

      if (isBinary) {
        promise.resolve(Base64.getEncoder().encodeToString(unsealed))
      } else {
        promise.resolve(unsealed.toString(Charsets.UTF_8))
      }
    } catch (e: javax.crypto.AEADBadTagException) {
      promise.reject("DecryptionError", "Bad auth tag exception", e)
    } catch (e: GeneralSecurityException) {
      promise.reject("DecryptionError", "Failed to decrypt", e)
    } catch (e: Exception) {
      promise.reject("DecryptionError", "Unexpected error", e)
    }
  }

  @ReactMethod
  fun decryptFile(inputFilePath: String,
                  outputFilePath: String,
                  key: String,
                  iv: String,
                  tag: String,
                  promise: Promise) {
    try {
      val keyData = Base64.getDecoder().decode(key)
      val secretKey: SecretKey = getSecretKeyFromString(keyData)
      val ivData = iv.hexStringToByteArray()
      val tagData = tag.hexStringToByteArray()

      val cipher = Cipher.getInstance("AES/GCM/NoPadding")
      val spec = GCMParameterSpec(GCM_TAG_LENGTH * 8, ivData)
      cipher.init(Cipher.DECRYPT_MODE, secretKey, spec)

      val buffer = ByteArray(BUFFER_SIZE)
      File(inputFilePath).inputStream().use { input ->
        File(outputFilePath).outputStream().use { output ->
          var bytesRead: Int
          while (input.read(buffer).also { bytesRead = it } != -1) {
            val decrypted = cipher.update(buffer, 0, bytesRead)
            if (decrypted != null && decrypted.isNotEmpty()) {
              output.write(decrypted)
            }
          }

          val finalDecrypted = cipher.doFinal(tagData)
          if (finalDecrypted.isNotEmpty()) {
            output.write(finalDecrypted)
          }
        }
      }

      promise.resolve(true)
    } catch (e: javax.crypto.AEADBadTagException) {
      Log.e("AesGcmCrypto", "File decryption failed with AEADBadTagException: ${e.message}", e)
      promise.reject("DecryptionError", "Bad auth tag exception", e)
    } catch (e: GeneralSecurityException) {
      Log.e("AesGcmCrypto", "File decryption failed with GeneralSecurityException: ${e.message}", e)
      promise.reject("DecryptionError", "Failed to decrypt", e)
    } catch (e: Exception) {
      Log.e("AesGcmCrypto", "File decryption failed with unexpected error: ${e.javaClass.simpleName} - ${e.message}", e)
      promise.reject("DecryptionError", "Unexpected error", e)
    }
  }

  @ReactMethod
  fun encrypt(plainText: String,
              inBinary: Boolean,
              key: String,
              promise: Promise) {
    try {
      val keyData = Base64.getDecoder().decode(key)
      val plainData = if (inBinary) Base64.getDecoder().decode(plainText) else plainText.toByteArray(Charsets.UTF_8)
      val sealed = encryptData(plainData, keyData)
      var response = WritableNativeMap()
      response.putString("iv", sealed.iv.toHex())
      response.putString("tag", sealed.tag.toHex())
      response.putString("content", Base64.getEncoder().encodeToString(sealed.ciphertext))
      promise.resolve(response)
    } catch (e: GeneralSecurityException) {
      Log.e("AesGcmCrypto", "Encryption failed with GeneralSecurityException: ${e.message}", e)
      promise.reject("EncryptionError", "Failed to encrypt", e)
    } catch (e: Exception) {
      Log.e("AesGcmCrypto", "Encryption failed with unexpected error: ${e.javaClass.simpleName} - ${e.message}", e)
      promise.reject("EncryptionError", "Unexpected error", e)
    }
  }

  @ReactMethod
  fun encryptFile(inputFilePath: String,
                  outputFilePath: String,
                  key: String,
                  promise: Promise) {
    try {
      val keyData = Base64.getDecoder().decode(key)
      val secretKey: SecretKey = getSecretKeyFromString(keyData)
      val cipher = Cipher.getInstance("AES/GCM/NoPadding")
      cipher.init(Cipher.ENCRYPT_MODE, secretKey)
      val iv = cipher.iv.copyOf()

      val buffer = ByteArray(BUFFER_SIZE)
      File(inputFilePath).inputStream().use { input ->
        File(outputFilePath).outputStream().use { output ->
          var bytesRead: Int
          while (input.read(buffer).also { bytesRead = it } != -1) {
            val encrypted = cipher.update(buffer, 0, bytesRead)
            if (encrypted != null && encrypted.isNotEmpty()) {
              output.write(encrypted)
            }
          }

          val finalBytes = cipher.doFinal()
          if (finalBytes.size >= GCM_TAG_LENGTH) {
            val ciphertext = finalBytes.copyOfRange(0, finalBytes.size - GCM_TAG_LENGTH)
            val tag = finalBytes.copyOfRange(finalBytes.size - GCM_TAG_LENGTH, finalBytes.size)
            output.write(ciphertext)

            var response = WritableNativeMap()
            response.putString("iv", iv.toHex())
            response.putString("tag", tag.toHex())
            promise.resolve(response)
          } else {
            output.write(finalBytes)
            var response = WritableNativeMap()
            response.putString("iv", iv.toHex())
            response.putString("tag", ByteArray(0).toHex())
            promise.resolve(response)
          }
        }
      }
    } catch (e: GeneralSecurityException) {
      promise.reject("EncryptionError", "Failed to encrypt: ${e.message}", e)
    } catch (e: OutOfMemoryError) {
      promise.reject("EncryptionError", "Out of memory: ${e.message}")
    } catch (e: Exception) {
      promise.reject("EncryptionError", "Unexpected error: ${e.javaClass.simpleName} - ${e.message}")
    }
  }
}