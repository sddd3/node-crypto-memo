export class InitializationVector {

    readonly value: string;
    constructor(value: string) {
        this.validate(value);
        this.value = value;
    }

    private validate(value: string) {
        // 必要なチェック処理を実装する。
    }
}