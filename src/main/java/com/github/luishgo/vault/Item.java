package com.github.luishgo.vault;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.stream.Stream;

import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import com.google.gson.JsonArray;

public class Item {
	
	private String uuid;
	
	private String typeName;
	
	private String title;
	
	private String location;
	
	private String updateAt;
	
	private String folderUUID;
	
	private int unknown = 0;
	
	private String trashed;
	
	ItemData data = new ItemData();

	public static Item newFromJSONArray(JsonArray array, Path basePath) {
		Item content = new Item();
		content.uuid = array.get(0).getAsString();
		content.typeName = array.get(1).getAsString();
		content.title = array.get(2).getAsString();
		content.location = array.get(3).getAsString();
		content.updateAt = array.get(4).getAsString();
		content.folderUUID = array.get(5).getAsString();
		content.unknown = array.get(6).getAsInt();
		content.trashed = array.get(7).getAsString();
		
		Gson gson = new GsonBuilder().create();
		try (Stream<String> details =Files.lines(basePath.resolve(content.uuid+".1password"))) {
			content.data = gson.fromJson(details.findFirst().get(), ItemData.class);
		} catch (IOException e) {
			e.printStackTrace();
		}
		
		return content;
	}

	public String getTitle() {
		return title;
	}
	
}
