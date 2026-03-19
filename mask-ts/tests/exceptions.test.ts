import { describe, test, expect, beforeEach, afterEach } from '@jest/globals';
import { 
  MaskError, 
  MaskVaultConnectionError, 
  MaskDecryptionError, 
  MaskNLPTimeout 
} from '../src/core/exceptions';
import * as maskPrivacy from '../src/index';

describe('TestExceptionHierarchy', () => {
  test('test_mask_error_is_exception', () => {
    const err = new MaskError("test");
    expect(err).toBeInstanceOf(Error);
  });

  test('test_vault_connection_error_inherits', () => {
    const err = new MaskVaultConnectionError("test");
    expect(err).toBeInstanceOf(MaskError);
  });

  test('test_decryption_error_inherits', () => {
    const err = new MaskDecryptionError("test");
    expect(err).toBeInstanceOf(MaskError);
  });

  test('test_nlp_timeout_inherits', () => {
    const err = new MaskNLPTimeout("test");
    expect(err).toBeInstanceOf(MaskError);
  });
});

describe('TestExceptionRaiseCatch', () => {
  test('test_catch_vault_error_as_mask_error', () => {
    expect(() => {
      throw new MaskVaultConnectionError("redis down");
    }).toThrow(MaskError);
  });

  test('test_catch_decryption_error_as_mask_error', () => {
    expect(() => {
      throw new MaskDecryptionError("bad key");
    }).toThrow(MaskError);
  });

  test('test_catch_nlp_timeout_as_mask_error', () => {
    expect(() => {
      throw new MaskNLPTimeout("took too long");
    }).toThrow(MaskError);
  });

  test('test_specific_catch_does_not_catch_sibling', () => {
    expect(() => {
      throw new MaskDecryptionError("bad key");
    }).toThrow(MaskDecryptionError);
    
    expect(() => {
      throw new MaskVaultConnectionError("redis gone");
    }).toThrow(MaskVaultConnectionError);

    try {
        throw new MaskVaultConnectionError("test");
    } catch (e) {
        expect(e).not.toBeInstanceOf(MaskDecryptionError);
    }
  });
});

describe('TestExceptionsExportedFromPackage', () => {
  test('test_import_from_mask', () => {
    expect(maskPrivacy).toHaveProperty("MaskError");
    expect(maskPrivacy).toHaveProperty("MaskVaultConnectionError");
    expect(maskPrivacy).toHaveProperty("MaskDecryptionError");
    expect(maskPrivacy).toHaveProperty("MaskNLPTimeout");
  });
});
