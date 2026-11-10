# Typical Workflow
1. Ingest Data, use SPL to filter and clean your data.
2. Fit (training): `| fit` to learn a model from the data.
3. Apply (application): `| apply` to use the model on new data.
4. Validation & Alerting: you verify if results are coherent and create alerts based on the predictions.
# MLTK App
## Showcase
### LLL Integrations
How to enrich your data with output from externally hosted Large Language Models.
### Predict Fields
To estimate a future numerical value (e.g., predicting CPU load).
- Field to predict: value you want to guess.
- Predictor fields: used by the algorithm to predict the target. Only select fields having impact on the target.
### Detecting outliers
To find what deviates from the norm (e.g., an unusual traffic spike).
### Time series forecasting
To predict the future based on the past (e.g., how many sales next month?).
### Event clustering
To group similar data without knowing the groups in advance (e.g., clustering user profiles).
## Essentials SPL Commands to Learn
### | fit
```
| fit <Algorithm> <Target_Field> from <Source_Fields> into <Model_Name>
```
Example
`| fit LinearRegression temperature from pressure into weather_model`

> Use the Linear Regression algorithm to learn how to predict temperature based on pressure, and save this knowledge in “weather_model”.

#### Persistent Model vs. Ephemeral Model
In MLTK, there are two ways to use the **| fit** command:
##### With into model_name (Persistent Model):
Splunk calculates the model, saves it to disk (in a lookup file), and applies it to the data.
Usefulness: This is used when you want to reuse this ‘knowledge’ later (for example, training the model on Monday and using it for alerts throughout the week).
##### Without into (Ephemeral Model / ‘On-the-fly’):
Splunk calculates the model in memory, applies it immediately to the data present to generate predictions, and then discards the model once the search is complete.
Nothing is saved to disk.
#### What are the available algorithms? Which ones should we know?
MLTK has around 30 algorithms mainly from scikit-learn. Knowing 5-6 can cover 90% of your needs.
Know the family instead of the algorithm.
##### Regression - Predicting temperature, disk space, latency.
- **LinearRegression**: the simplest and fastest. It draws a straight line through your data. This is the ideal starting point.
- **RandomForestRegressor**: More powerful. It uses a ‘forest’ of decision trees. Use this if the relationship between your data is not a simple straight line (e.g. the disk fills up exponentially).
##### Classification - Is it fraud or not? Will the disk crash (Yes/No)?
- **LogisticRegression**: Despite its name, it is for classification. It is the standard for answering Yes/No (binary).
- **RandomForestClassifier**: As with regression, this is the ‘powerful’ version for complex data with a lot of noise.
##### Anomaly Detection - Detect an abnormal CPU spike or intrusion.
- **DensityFunction**  (The most important in Splunk): This is the star of MLTK. It learns the normal ‘shape’ of your data (the Gaussian/Bell curve) and flags anything that deviates too far from this normality. This is the one you will use most often for alerting
##### Time Series - Predict next week's network traffic.
- **StateSpaceForecast**: Specially designed for time series data. It understands the concept of ‘seasonality’ (e.g., traffic drops at night and on weekends.

Master LinearRegression (for numbers), DensityFunction (for anomalies) and StateSpaceForecast (for time). The others will come with experience.

#### What is the model? Is it something we create for each use case or does it already exists?
We create model for each use case.
When doing: `| fit LinearRegression ... into my_disk_model`
1. Splunk does mathematical calculations.
2. Splunk generates a file (binary, usually a "pickle" python object)
3. Splunk saves the file under the name my_disk_model in Splunk Lookups.
A model is specific to **your data**. A model trained on Linux servers won't work well on Windows for example.
A model ages. If your infrastructure changes, the ‘notebook’ becomes obsolete. You must therefore retrain (refit) regularly (for example, every night via a Scheduled Search) to update the model.
### | apply
```
| apply weather_model`
```

> Take the new incoming data and use “weather_model” to guess the temperature.

### | summary <Model_Name>
Allows you to view the technical details and coefficients of your model.
## Experiments
"Low-Code" UI.
- Select your data.
- Select the algorithm.
- It generates the SPL and displays visualisation of the results.
- Allows you to convert the experience in an alert or dashboard in one click.

### | predict 
```
    | predict usage algorithm=LLP5 future_timespan=14 holdback=0 
```
From Splunk Enterprise. The predict command specialises in one thing: **forecasting univariate time series** (predicting a numerical value over time based solely on its past).
#### Parameters
##### algorithm
It's the engine under the bonnet. Splunk offers several, but there are three to remember:
- **LLP** (Local Linear Prediction): The default algorithm. It's good for guessing a trend (up or down) but bad for understanding cycles (seasonality). It's very sensitive to noise (it reacts quickly to spikes).
- **LLP5**: This is an improved version of LLP. It smooths the data more before making predictions. This is the one I recommend 90% of the time for IT (CPU, disk, licence) because our data is often ‘noisy’ (small spikes everywhere).
- **LLT** (Local Linear Trend): Use this if your data has very strong and clear seasonality (e.g. web traffic that makes perfect waves day/night). It is heavier to calculate.
##### futur_timespan
How many points in the future? (e.g., future_timespan=14 for 14 days if your span=1d).
##### holdback
The testing tool. If you set holdback=5, Splunk hides the last 5 actual days from the algorithm, makes the prediction, and allows you to compare ‘Prediction vs Reality’ to see if the algorithm is reliable.
##### upper/lower
Allows you to set the confidence interval (default 95%). This is what draws the grey area around the curve.