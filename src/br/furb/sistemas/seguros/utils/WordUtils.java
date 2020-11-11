package br.furb.sistemas.seguros.utils;

import java.util.ArrayList;
import java.util.List;

import br.furb.sistemas.seguros.aes.AesConstants;

/**
 * Utilitário para implementações relacionadas a palavras de Round Keys.
 * 
 * @see RoundKeyUtils
 */
public class WordUtils {

	/**
	 * Realiza a operação XOR para duas palavras da Round Key.
	 * 
	 * @param word1 palavra 1
	 * @param word2 palavra 2
	 * @return uma nova palavra com a operação XOR das duas palavras parametrizadas
	 */
	public static String[] doXor(String[] word1, String[] word2) {
		String[] xor = new String[AesConstants.MATRIX_LENGTH];
		for (int i = 0; i < xor.length; i++) {
			int hex1 = CryptUtils.hexToInt(word1[i]);
			int hex2 = CryptUtils.hexToInt(word2[i]);
			xor[i] = Integer.toHexString(hex1 ^ hex2);
		}
		return xor;
	}

	/**
	 * Realiza a substituição dos valores hexadecimais da palavra conforme a {@link AesConstants#sbox}.
	 * 
	 * @param word palavra a ter os valores substituídos
	 * @return uma nova palavra gerada da substituição
	 */
	public static String[] doSub(String[] word) {
		List<String> subWord = new ArrayList<>();
		for (int i = 0; i < word.length; i++) {
			int hex = CryptUtils.hexToInt(String.valueOf(word[i]));
			int value = AesConstants.sbox[hex / 16][hex % 16];
			subWord.add(Integer.toHexString(value));
		}
		return subWord.stream().toArray(String[]::new);
	}

	/**
	 * Rotaciona os bytes da palavra.
	 * 
	 * @param word palavra
	 * @return uma nova palavra com os bytes rotacionados
	 */
	public static String[] doRot(String[] word) {
		return new String[] { word[1], word[2], word[3], word[0] };
	}

	/**
	 * Gera a Round Constant da Round Key conforme a tabela {@link AesConstants#roundConstant}.
	 * 
	 * @param roundKeyIndex índice da Round Key a ter seu valor encontrado na tabela constante
	 * @return uma nova palavra contendo os valores da Round Constant
	 */
	public static String[] doRoundConstant(int roundKeyIndex) {
		int roundConstantValue = AesConstants.roundConstant[roundKeyIndex - 1];
		String firstValue = Integer.toHexString(roundConstantValue);
		String defaultValue = "0";
		return new String[] { firstValue, defaultValue, defaultValue, defaultValue };
	}

}
