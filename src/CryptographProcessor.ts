import crypto from 'crypto';
import { CommonKey } from './domainObject/CommonKey';
import { InitializationVector } from './domainObject/InitializationVector';
import { Password } from './domainObject/Password';
import { Salt } from './domainObject/Salt';

export class CryptographProcessor {
    private readonly algorithm = 'aes-256-cbc';
    private readonly keyLength = 32;
    private readonly inputEncoding = 'utf8';
    private readonly outputEncoding = 'hex';

    main(target: string): string[] {
        const password = new Password(this.createRandomBytes(16));
        const salt = new Salt(this.createRandomBytes(16));
        /** 初期化ベクトル  */
        const iv = new InitializationVector(this.createRandomBytes(16));

        console.log(`password.value: ${password.value}`);
        console.log(`salt.value: ${salt.value}`);
        console.log(`iv.value: ${iv.value}`);
        /** 暗号化に使用する共通鍵 */
        const commonKey = this.createCommonKey(password, salt);
        console.log(`commonKey: ${commonKey.value}`);

        const cipher = this.createCipher(commonKey, iv);
        const encryptionedData = this.encryption(cipher, target);

        const decipher = this.createDecipher(commonKey, iv);
        const decryptionedData = this.decryption(decipher, encryptionedData);

        console.log(`暗号化したデータ: ${encryptionedData}`);
        console.log(`複合化したデータ: ${decryptionedData}`);

        /**
         * 実際のプログラムでは、暗号化の処理と複合化の処理を同じ処理で行うことはないと思います。
         * しかし、共通鍵暗号方式なので暗号化に使用した共通鍵と初期化ベクトルと同じ共通鍵と初期化ベクトルが複合化の際に必要になります。
         * そのため、共通鍵と初期化ベクトルをどこかに保存する必要がありますが、暗号化されたデータ・共通鍵・初期化ベクトルを同じDBに保存してしまうと
         * DBの内容が盗まれた際に暗号化した意味がなくなってしまいます。
         * そのため、共通鍵暗号方式を使用する際は、暗号化されたデータ・共通鍵・初期化ベクトルの保存先をよく検討する必要があります。
         */
        return [encryptionedData, decryptionedData];
    }

    /**
     * 暗号的に強い疑似乱数データを生成します。size引数には生成するバイト数を示す数値を指定します。
     * randomBytesはBuffer型を返却してくるのでstring型に変換しています。
     * Buffer型をstring型に変換する必要はありませんが、console.logで確認し易いようにここでは変換しています。
     * @param size バイト数
     * @returns 議事乱数データ
     */
    private createRandomBytes(size: number): string {
        return crypto.randomBytes(size).toString('base64').substring(0, size);
    }

    /**
     * Scryptはパスワードベースの鍵生成機能です。
     * パスワードベース暗号化方式は、入力されたパスワードを元に鍵を生成し暗号化を行う共通鍵暗号化アルゴリズムです。
     * ソルトはランダムで、少なくとも16バイトの長さが推奨されています。
     * scryptSyncは同期型関数です。
     * この関数でも、console.logで確認し易いようにBuffer型をstring型に変更していますが、実際は変更する必要はありません。
     * @param password 暗号化キーを生成するためのパスワード
     * @param salt 暗号化キーを生成するためのソルト
     * @returns 暗号化キー
     */
    private createCommonKey(password: Password, salt: Salt): CommonKey {
        const key = crypto.scryptSync(password.value, salt.value, this.keyLength).toString('base64').substring(0, this.keyLength);
        const commonKey = new CommonKey(key);
        return commonKey;

    }

    /**
     * Cipherクラスのインスタンスは、データの暗号化に使用されます。
     * cipher.update()メソッドとcipher.final()メソッドを使用して、暗号化されたデータを生成します。
     * Cipherインスタンスの作成には、crypto.createCipher()またはcrypto.createCipheriv()メソッドを使用します。
     * Cipherオブジェクトをnewキーワードで直接作成してはいけません。
     * Cipherオブジェクトを作成する際に使用した共通鍵と初期化ベクトルは複合化する際にも使用します。
     * そのため、実運用では共通鍵と初期化ベクトルはどこかに保存する必要があります。
     * @param commonKey 共通鍵
     * @param iv 初期化ベクトル
     * @returns Cihperオブジェクト
     */
    private createCipher(commonKey: CommonKey, iv: InitializationVector): crypto.Cipher {
        return crypto.createCipheriv(this.algorithm, commonKey.value, iv.value);
    }

    /**
     * Decipherクラスのインスタンスは、データの複合化に使用されます。
     * decipher.update()メソッドはdecipher.final()メソッドを使用して、暗号化されていないデータを生成します。
     * Decipherインスタンスの生成には、crypto.createDecipher()またはcrypto.createDecipheriv()メソッドを使用します。
     * Decipherオブジェクトはnewキーワードを使用して直接作成してはいけません。
     * Decipherクラスのインスタンスを作成する際に使用する、共通鍵と初期化ベクトルは暗号化した際に使用したものと同じものが必要です。
     * そのため、実運用では共通鍵と初期化ベクトルはどこかに保存する必要があります。
     * @param commonKey 共通鍵
     * @param iv 初期化ベクトル
     * @returns Decipherオブジェクト
     */
    private createDecipher(commonKey: CommonKey, iv: InitializationVector): crypto.Decipher {
        return crypto.createDecipheriv(this.algorithm, commonKey.value, iv.value);
    }

    /**
     * 引数で受け取ったtargetを暗号化し、暗号化したデータを返却します。
     * @param cipher cipherオブジェクト
     * @param target 暗号化させたいデータ
     * @returns 暗号化されたデータ
     */
    private encryption(cipher: crypto.Cipher, target: string): string {
        let encryptionedData = cipher.update(target, this.inputEncoding, this.outputEncoding);
        encryptionedData += cipher.final(this.outputEncoding);
        return encryptionedData;
    }

    /**
     * 引数で受け取ったtargetを複合化し、複合化したデータを返却します。
     * @param decipher decipherオブジェクト
     * @param target 複合化したいデータ
     * @returns 複合化されたデータ
     */
    private decryption(decipher: crypto.Decipher, target: string): string {
        let decryptionData = decipher.update(target, this.outputEncoding, this.inputEncoding);
        decryptionData += decipher.final(this.inputEncoding);
        return decryptionData;
    }
}