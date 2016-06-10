package com.github.luishgo.vault;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.stream.Stream;

import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import com.google.gson.JsonArray;
import com.google.gson.annotations.Expose;

public class Item {
	
	@Expose private String uuid;
	
	@Expose private String typeName;
	
	@Expose private String title;
	
	@Expose private String domain;
	
	@Expose private String updateAt;
	
	@Expose private String folderUUID;
	
	@Expose private int passwordStrength = 0;
	
	@Expose private String trashed;
	
	@Expose protected ItemData data;

	private Path basePath;

	public Item(Path basePath) {
		this.basePath = basePath;
	}

	public static Item newFromJSONArray(JsonArray array, Path basePath) {
		Item content = new Item(basePath);
		content.uuid = array.get(0).getAsString();
		content.typeName = array.get(1).getAsString();
		content.title = array.get(2).getAsString();
		content.domain = array.get(3).getAsString();
		content.updateAt = array.get(4).getAsString();
		content.folderUUID = array.get(5).getAsString();
		content.passwordStrength = array.get(6).getAsInt();
		content.trashed = array.get(7).getAsString();
		
		return content;
	}

	public String getTitle() {
		return title;
	}
	
	public Path getDataPath() {
		return basePath.resolve(this.uuid+".1password");
	}
	
	public ItemData getData() {
		if (this.data == null) {
			Gson gson = new GsonBuilder().create();
			try (Stream<String> details =Files.lines(getDataPath())) {
				this.data = gson.fromJson(details.findFirst().get(), ItemData.class);
			} catch (IOException e) {
				e.printStackTrace();
			}
		}
		return this.data;
	}
	
}
