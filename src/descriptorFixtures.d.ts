export declare const fixtures: {
    valid: ({
        descriptor: string;
        script: string;
        checksumRequired: boolean;
        index?: undefined;
    } | {
        descriptor: string;
        script: string;
        index: number;
        checksumRequired: boolean;
    } | {
        descriptor: string;
        script: string;
        checksumRequired?: undefined;
        index?: undefined;
    })[];
    invalid: ({
        descriptor: string;
        checksumRequired: boolean;
    } | {
        descriptor: string;
        checksumRequired?: undefined;
    })[];
};
