from transformers import DetrFeatureExtractor, DetrForObjectDetection
import torch
from PIL import Image
import requests


url = "http://images.cocodataset.org/val2017/000000039769.jpg"
image = Image.open(requests.get(url, stream=True).raw)


model_dir = "/Users/alrivero/Documents/CSE_508/mal_bins/detr/test"
feature_extractor = DetrFeatureExtractor.from_pretrained(model_dir)
model = DetrForObjectDetection.from_pretrained(model_dir)

inputs = feature_extractor(images=image, return_tensors="pt")
outputs = model(**inputs)

# convert outputs (bounding boxes and class logits) to COCO API
target_sizes = torch.tensor([image.size[::-1]])
results = feature_extractor.post_process(outputs, target_sizes=target_sizes)[0]
for score, label, box in zip(results["scores"], results["labels"], results["boxes"]):
    box = [round(i, 2) for i in box.tolist()]
    # let's only keep detections with score > 0.9
    if score > 0.9:
        print(
            f"Detected {model.config.id2label[label.item()]} with confidence "
            f"{round(score.item(), 3)} at location {box}"
        )