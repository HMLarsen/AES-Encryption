package br.furb.sistemas.seguros.utils;

import br.furb.sistemas.seguros.aes.AesConstants;

/**
 * Utilitário para implementações relacionadas a Round Keys.
 * 
 * @see WordUtils
 */
public class RoundKeyUtils {

	private static final int MATRIX_LENGTH = AesConstants.MATRIX_LENGTH;

	/**
	 * Cria uma Round Key com base nas palavras parametrizadas e seus índices correspondentes.
	 * 
	 * @param word1 palavra 1
	 * @param word2 palavra 2
	 * @param word3 palavra 3
	 * @param word4 palavra 4
	 * @return a Round Key criada com as palavras parametrizadas
	 */
	public static String[][] createRoundKey(String[] word1, String[] word2, String[] word3, String[] word4) {
		String[][] newRoundKey = new String[MATRIX_LENGTH][MATRIX_LENGTH];
		RoundKeyUtils.fillWord(newRoundKey, word1, 0);
		RoundKeyUtils.fillWord(newRoundKey, word2, 1);
		RoundKeyUtils.fillWord(newRoundKey, word3, 2);
		RoundKeyUtils.fillWord(newRoundKey, word4, 3);
		return newRoundKey;
	}

	/**
	 * Preenche a palavra parametrizada na Round Key conforme o índice.
	 * 
	 * @param matrix Round Key a ter a palavra substituída
	 * @param word palavra a substituir
	 * @param wordIndex índice da palavra na Round Key (coluna na matriz)
	 */
	public static void fillWord(String[][] matrix, String[] word, int wordIndex) {
		for (int line = 0; line < MATRIX_LENGTH; line++) {
			matrix[line][wordIndex] = word[line];
		}
	}

	/**
	 * Realiza a operação XOR para todos os valores das Round Keys.
	 * 
	 * @param matrix1 Round Key 1
	 * @param matrix2 Round Key 2
	 * @return uma nova Round Key com o resultado da operação XOR entre as matrizes
	 * @see WordUtils#doXor(String[], String[])
	 */
	public static String[][] doXor(String[][] matrix1, String[][] matrix2) {
		String[][] xor = new String[MATRIX_LENGTH][MATRIX_LENGTH];
		for (int i = 0; i < xor.length; i++) {
			xor[i] = WordUtils.doXor(matrix1[i], matrix2[i]);
		}
		return xor;
	}

	/**
	 * Realiza a substituição das palavras das Round Keys conforme a
	 * {@link AesConstants#sbox}.
	 * 
	 * @param matrix Round Key
	 * @return uma nova Round Key com o resultado da substituição dos valores
	 * @see WordUtils#doSub(String[])
	 */
	public static String[][] doSubBytes(String[][] matrix) {
		String[][] subBytes = new String[MATRIX_LENGTH][MATRIX_LENGTH];
		for (int i = 0; i < subBytes.length; i++) {
			subBytes[i] = WordUtils.doSub(matrix[i]);
		}
		return subBytes;
	}

	/**
	 * Embaralha os valores da Round Key.<br>
	 * Deve rotacionar os valores X vezes para a esquerda conforme a linha corrente.
	 * 
	 * @param matrix Round Key
	 * @return uma nova Round Key com o resultado embaralhado
	 */
	public static String[][] doShiftRows(String[][] matrix) {
		String[][] subBytes = matrix.clone();
		for (int i = 1; i < subBytes.length; i++) {
			subBytes[i] = leftRotate(subBytes[i], i);
		}
		return subBytes;
	}

	/**
	 * Rotaciona a palavra da Round Key para a esquerda conforme o @param times.
	 * 
	 * @param word palavra da Round Key
	 * @param times número de vezes para rotacionar
	 * @return a palavra da Round Key embaralhada
	 */
	private static String[] leftRotate(String[] word, int times) {
		if (times % MATRIX_LENGTH == 0) {
			return word;
		}
		while (times > 0) {
			String temp = word[0];
			for (int i = 0; i < word.length - 1; i++) {
				word[i] = word[i + 1];
			}
			word[word.length - 1] = temp;
			--times;
		}
		return word;
	}

	/**
	 * Realiza a etapa Mix Columns da criptografia.
	 * 
	 * @param matrix matriz resultante da etapa ShiftRows
	 * @return uma nova Round Key com o resultado das operações
	 */
	public static String[][] doMixColumns(String[][] matrix) {
		String[][] resultMatrix = new String[MATRIX_LENGTH][MATRIX_LENGTH];
		int[][] multiMatrix = AesConstants.multiMatrix;
		for (int line = 0; line < resultMatrix.length; line++) {
			for (int column = 0; column < resultMatrix.length; column++) {
				// valores da matriz ShiftRows
				int matrixValue1 = CryptUtils.parseHexToInt(matrix[0][line]);
				int matrixValue2 = CryptUtils.parseHexToInt(matrix[1][line]);
				int matrixValue3 = CryptUtils.parseHexToInt(matrix[2][line]);
				int matrixValue4 = CryptUtils.parseHexToInt(matrix[3][line]);

				// valores da matriz de multiplicação
				int multiValue1 = multiMatrix[column][0];
				int multiValue2 = multiMatrix[column][1];
				int multiValue3 = multiMatrix[column][2];
				int multiValue4 = multiMatrix[column][3];

				// valores da operação de Galois
				int galoisValue1 = getGaloisOperation(matrixValue1, multiValue1);
				int galoisValue2 = getGaloisOperation(matrixValue2, multiValue2);
				int galoisValue3 = getGaloisOperation(matrixValue3, multiValue3);
				int galoisValue4 = getGaloisOperation(matrixValue4, multiValue4);

				// XOR com os valores resultantes
				int operation = galoisValue1 ^ galoisValue2 ^ galoisValue3 ^ galoisValue4;
				resultMatrix[column][line] = Integer.toHexString(operation);
			}
		}
		return resultMatrix;
	}

	/**
	 * Realiza a multiplicação de Galois.<br>
	 * Pega os valores correspondes dos termos na tabela {@link AesConstants#lTable} e soma esses valores.<br>
	 * Se a soma for maior que <code>0xff</code> então é subtraído <code>0xff</code> da soma.<br>
	 * O valor da soma é pego da correspondência na {@link AesConstants#eTable}.
	 * Exceções:<br>
	 * Se o primeiro termo for 0 então o resultado é 0.<br>
	 * Se o primeiro ou segundo termo forem 1 então o resultado é outro termo.<br>
	 * 
	 * @param hex1 termo 1
	 * @param hex2 termo 2
	 * @return
	 */
	private static int getGaloisOperation(int hex1, int hex2) {
		if (hex1 == 0) {
			return 0;
		}
		if (hex1 == 1) {
			return hex2;
		}
		if (hex2 == 1) {
			return hex1;
		}
		int value1 = AesConstants.lTable[hex1 / 16][hex1 % 16];
		int value2 = AesConstants.lTable[hex2 / 16][hex2 % 16];
		int sum = value1 + value2;
		if (sum > 0xff) {
			sum -= 0xff;
		}
		return getTableEValue(sum);
	}

	/**
	 * @param hex valor inteiro do hexadecimal
	 * @return valor correspondente do hexadecimal na {@link AesConstants#eTable}
	 */
	private static int getTableEValue(int hex) {
		return AesConstants.eTable[hex / 16][hex % 16];
	}

}
