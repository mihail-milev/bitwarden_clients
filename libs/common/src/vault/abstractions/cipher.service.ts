import { UriMatchStrategySetting } from "../../models/domain/domain-service";
import { SymmetricCryptoKey } from "../../platform/models/domain/symmetric-crypto-key";
import { CipherId, CollectionId, OrganizationId } from "../../types/guid";
import { CipherType } from "../enums/cipher-type";
import { CipherData } from "../models/data/cipher.data";
import { Cipher } from "../models/domain/cipher";
import { Field } from "../models/domain/field";
import { CipherView } from "../models/view/cipher.view";
import { FieldView } from "../models/view/field.view";

export abstract class CipherService {
  clearCache: (userId?: string) => Promise<void>;
  encrypt: (
    model: CipherView,
    keyForEncryption?: SymmetricCryptoKey,
    keyForCipherKeyDecryption?: SymmetricCryptoKey,
    originalCipher?: Cipher,
  ) => Promise<Cipher>;
  encryptFields: (fieldsModel: FieldView[], key: SymmetricCryptoKey) => Promise<Field[]>;
  encryptField: (fieldModel: FieldView, key: SymmetricCryptoKey) => Promise<Field>;
  get: (id: string) => Promise<Cipher>;
  getAll: () => Promise<Cipher[]>;
  getAllDecrypted: () => Promise<CipherView[]>;
  getAllDecryptedForGrouping: (groupingId: string, folder?: boolean) => Promise<CipherView[]>;
  getAllDecryptedForUrl: (
    url: string,
    includeOtherTypes?: CipherType[],
    defaultMatch?: UriMatchStrategySetting,
  ) => Promise<CipherView[]>;
  getAllFromApiForOrganization: (organizationId: string) => Promise<CipherView[]>;
  /**
   * Gets ciphers belonging to the specified organization that the user has explicit collection level access to.
   * Ciphers that are not assigned to any collections are only included for users with admin access.
   */
  getManyFromApiForOrganization: (organizationId: string) => Promise<CipherView[]>;
  getLastUsedForUrl: (url: string, autofillOnPageLoad: boolean) => Promise<CipherView>;
  getLastLaunchedForUrl: (url: string, autofillOnPageLoad: boolean) => Promise<CipherView>;
  getNextCipherForUrl: (url: string) => Promise<CipherView>;
  updateLastUsedIndexForUrl: (url: string) => void;
  updateLastUsedDate: (id: string) => Promise<void>;
  updateLastLaunchedDate: (id: string) => Promise<void>;
  saveNeverDomain: (domain: string) => Promise<void>;
  createWithServer: (cipher: Cipher, orgAdmin?: boolean) => Promise<any>;
  updateWithServer: (cipher: Cipher, orgAdmin?: boolean, isNotClone?: boolean) => Promise<any>;
  shareWithServer: (
    cipher: CipherView,
    organizationId: string,
    collectionIds: string[],
  ) => Promise<any>;
  shareManyWithServer: (
    ciphers: CipherView[],
    organizationId: string,
    collectionIds: string[],
  ) => Promise<any>;
  saveAttachmentWithServer: (
    cipher: Cipher,
    unencryptedFile: any,
    admin?: boolean,
  ) => Promise<Cipher>;
  saveAttachmentRawWithServer: (
    cipher: Cipher,
    filename: string,
    data: ArrayBuffer,
    admin?: boolean,
  ) => Promise<Cipher>;
  saveCollectionsWithServer: (cipher: Cipher) => Promise<any>;
  /**
   * Bulk update collections for many ciphers with the server
   * @param orgId
   * @param cipherIds
   * @param collectionIds
   * @param removeCollections - If true, the collections will be removed from the ciphers, otherwise they will be added
   */
  bulkUpdateCollectionsWithServer: (
    orgId: OrganizationId,
    cipherIds: CipherId[],
    collectionIds: CollectionId[],
    removeCollections: boolean,
  ) => Promise<void>;
  upsert: (cipher: CipherData | CipherData[]) => Promise<any>;
  replace: (ciphers: { [id: string]: CipherData }) => Promise<any>;
  clear: (userId: string) => Promise<any>;
  moveManyWithServer: (ids: string[], folderId: string) => Promise<any>;
  delete: (id: string | string[]) => Promise<any>;
  deleteWithServer: (id: string, asAdmin?: boolean) => Promise<any>;
  deleteManyWithServer: (ids: string[], asAdmin?: boolean) => Promise<any>;
  deleteAttachment: (id: string, attachmentId: string) => Promise<void>;
  deleteAttachmentWithServer: (id: string, attachmentId: string) => Promise<void>;
  sortCiphersByLastUsed: (a: CipherView, b: CipherView) => number;
  sortCiphersByLastUsedThenName: (a: CipherView, b: CipherView) => number;
  getLocaleSortingFunction: () => (a: CipherView, b: CipherView) => number;
  softDelete: (id: string | string[]) => Promise<any>;
  softDeleteWithServer: (id: string, asAdmin?: boolean) => Promise<any>;
  softDeleteManyWithServer: (ids: string[], asAdmin?: boolean) => Promise<any>;
  restore: (
    cipher: { id: string; revisionDate: string } | { id: string; revisionDate: string }[],
  ) => Promise<any>;
  restoreWithServer: (id: string, asAdmin?: boolean) => Promise<any>;
  restoreManyWithServer: (
    ids: string[],
    organizationId?: string,
    asAdmin?: boolean,
  ) => Promise<void>;
  getKeyForCipherKeyDecryption: (cipher: Cipher) => Promise<any>;
}
