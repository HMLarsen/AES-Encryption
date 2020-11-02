package br.furb.sistemas.seguros.aes;

import java.util.ArrayList;
import java.util.List;

import br.furb.sistemas.seguros.utils.CryptUtils;
import br.furb.sistemas.seguros.utils.RoundKeyUtils;
import br.furb.sistemas.seguros.utils.WordUtils;

/**
 * Tabela Key Schedule para armazenar as Round Keys conforme a expansão da chave de criptografia AES.
 */
public class KeySchedule {

	private static final int MATRIX_LENGTH = AesConstants.MATRIX_LENGTH;
	private static final int TABLE_LENGHT = 11;
	private List<String[][]> roundKeys = new ArrayList<>();

	/**
	 * Inicializa a tabela das Round Keys e faz a expansão da chave.
	 * 
	 * @param key chave a ser expandida
	 */
	public KeySchedule(String[][] key) {
		roundKeys.add(key.clone());
		AesCrypt.doLog("**** RoundKey=0 ****");
		AesCrypt.doRoundKeyLog(roundKeys.get(0));

		// repetição para gerar as outras chaves e preencher a tabela
		for (int i = 1; i < TABLE_LENGHT; i++) {
			fillRoundKey(i);
		}
	}

	/**
	 * Cria uma Round Key na lista conforme especificações.
	 * 
	 * @param roundKeyIndex índice da Round Key sendo gerada
	 */
	private void fillRoundKey(int roundKeyIndex) {
		AesCrypt.doLog("**** RoundKey=" + roundKeyIndex + " ****");

		String[] firstWord = generateFirstWord(roundKeyIndex);
		String[] secondWord = WordUtils.doXor(getLastRoundKeyWord(roundKeyIndex, 1), firstWord);
		String[] thirdWord = WordUtils.doXor(getLastRoundKeyWord(roundKeyIndex, 2), secondWord);
		String[] fourthWord = WordUtils.doXor(getLastRoundKeyWord(roundKeyIndex, 3), thirdWord);

		String[][] newRoundKey = RoundKeyUtils.createRoundKey(firstWord, secondWord, thirdWord, fourthWord);
		roundKeys.add(newRoundKey);

		AesCrypt.doRoundKeyLog(newRoundKey);
	}

	/**
	 * Cria a primeira palavra da Round Key.
	 * 
	 * @param roundKeyIndex índice da Round Key sendo gerada
	 * @return a primeira palavra da Round Key gerada
	 */
	private String[] generateFirstWord(int roundKeyIndex) {
		AesCrypt.doLog("\n\n   Etapas para geração da primeira word");

		String[] lastWord = getLastRoundKeyWord(roundKeyIndex, 3);
		AesCrypt.doLog("\n\n   1) Cópia da última palavra da roundkey anterior: " + CryptUtils.wordToString(lastWord));

		String[] rotWord = WordUtils.doRot(lastWord);
		AesCrypt.doLog("\n\n   2) Rotacionar os bytes desta palavra (RotWord): " + CryptUtils.wordToString(rotWord));

		String[] subWord = WordUtils.doSub(rotWord);
		AesCrypt.doLog("\n\n   3) Substituir os bytes da palavra (SubWord): " + CryptUtils.wordToString(subWord));

		String[] roundConstantWord = WordUtils.doRoundConstant(roundKeyIndex);
		AesCrypt.doLog("\n\n   4) Gerar a RoundConstant: " + CryptUtils.wordToString(roundConstantWord));

		String[] xorSubWordAndConstantWord = WordUtils.doXor(subWord, roundConstantWord);
		AesCrypt.doLog("\n\n   5) XOR de (3) com (4): " + CryptUtils.wordToString(xorSubWordAndConstantWord));

		String[] xorFirstWordAnd5 = WordUtils.doXor(getLastRoundKeyWord(roundKeyIndex, 0), xorSubWordAndConstantWord);
		AesCrypt.doLog("\n\n   6) XOR 1a. palavra da roundkey anterior com (5): " + CryptUtils.wordToString(xorFirstWordAnd5) + "\n");
		return xorFirstWordAnd5;
	}

	/**
	 * Método auxiliar para pegar uma palavra da última Round Key gerada.
	 * 
	 * @param roundKeyIndex índice da Round Key sendo gerada
	 * @param wordIndex     índice da palavra a ser retornada
	 * @return uma nova palavra contendo o valor da palavra a ser encontrada
	 */
	private String[] getLastRoundKeyWord(int roundKeyIndex, int wordIndex) {
		String[] word = new String[MATRIX_LENGTH];
		String[][] lastRoundKey = roundKeys.get(roundKeyIndex - 1);
		for (int line = 0; line < word.length; line++) {
			word[line] = lastRoundKey[line][wordIndex];
		}
		return word;
	}

	public List<String[][]> getRoundKeys() {
		return roundKeys;
	}

}
