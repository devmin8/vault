export type KdfParams = {
	salt: string;
	memory: number;
	iterations: number;
	parallelism: number;
};

export type VaultData = {
	version: 1;
	updatedAt: string;
	entries: Record<string, string>;
};
