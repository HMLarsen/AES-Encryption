package br.furb.sistemas.seguros.utils;

import java.io.File;
import java.nio.file.Files;
import java.util.ArrayList;
import java.util.List;
import java.util.StringTokenizer;

import br.furb.sistemas.seguros.aes.AesConstants;

/**
 * Utilitário para implementações de criptografia.
 */
public class CryptUtils {

	private static final int MATRIX_LENGTH = AesConstants.MATRIX_LENGTH;

	/**
	 * Retorna uma matriz em hexadecimal a partir da chave informada.<br>
	 * A chave informada deve ser representada em bytes separados por "," e de tamanho 16.
	 * 
	 * @param key chave a gerar a matriz 4x4
	 * @return matriz de {@link String} com os bytes em hexadecimais
	 */
	public static String[][] getKeyMatrix(String key) {
		String[][] keyMatrix = new String[MATRIX_LENGTH][MATRIX_LENGTH];
		StringTokenizer tokenizer = new StringTokenizer(key, ",");
		for (int column = 0; column < keyMatrix.length; column++) {
			for (int line = 0; line < keyMatrix.length; line++) {
				keyMatrix[line][column] = Integer.toHexString(Integer.parseInt(tokenizer.nextToken()));
			}
		}
		return keyMatrix;
	}

	/**
	 * Retorna uma lista de matrizes em hexadecimal conforme os bytes do arquivo.<br>
	 * As matrizes terão blocos de 16 bytes e preenchimento PKCS#5.
	 * 
	 * @param fileToCrypt arquivo a ser criptografado
	 * @return lista de matrizes conforme os bytes do arquivo a criptografar
	 * @throws Exception erros na leitura do arquivo
	 * @see {@link Pkcs5}
	 */
	public static List<String[][]> getMatricesFileToCrypt(File fileToCrypt) throws Exception {
		List<String[][]> matrices = new ArrayList<>();
		byte[] fileBytes = Files.readAllBytes(fileToCrypt.toPath());
		int fileBytesSize = fileBytes.length;
		if (fileBytesSize <= 0) {
			return matrices;
		} else {
			int line = 0;
			int column = 0;
			String[][] matrix = new String[MATRIX_LENGTH][MATRIX_LENGTH];
			matrices.add(matrix);

			// percorrer os bytes do arquivo e preencher as colunas das matrizes
			for (int i = 0; i < fileBytesSize; i++) {
				// se as linhas terminaram, iniciar a nova coluna
				if (line > 3) {
					line = 0;
					column++;
				}
				// se as colunas terminaram, iniciar uma nova matriz
				if (column > 3) {
					matrix = new String[MATRIX_LENGTH][MATRIX_LENGTH];
					matrices.add(matrix);
					line = 0;
					column = 0;
				}
				byte b = fileBytes[i];
				matrix[line++][column] = byteToHex(b);
			}
		}
		Pkcs5.doPadding(matrices);
		return matrices;
	}

	/**
	 * @param word palavra da roundKey
	 * @return representação em linha da palavra formatada em hexadecimal
	 */
	public static String wordToString(String[] word) {
		String value1 = formatHex(word[0]);
		String value2 = formatHex(word[1]);
		String value3 = formatHex(word[2]);
		String value4 = formatHex(word[3]);
		return "[" + value1 + " " + value2 + " " + value3 + " " + value4 + "]";
	}

	/**
	 * @param hex representação hexadecimal
	 * @return hexadecimal formatado corretamente
	 */
	public static String formatHex(String hex) {
		return String.format("0x%02x", hexToInt(hex));
	}

	/**
	 * @param hex texto representativo do hexadecimal
	 * @return o valor inteiro equivalente ao hexadecimal representado
	 */
	public static int hexToInt(String hex) {
		return Integer.parseInt(hex, 16);
	}

	/**
	 * @param value byte a ser representado
	 * @return representação hexadecimal para o byte correspondente
	 */
	public static String byteToHex(byte value) {
		return String.format("%02x", value);
	}

}
