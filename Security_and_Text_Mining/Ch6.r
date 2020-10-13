rm(list=ls()) #Start with a clean slate: remove any and all objects

#Load libraries
library(tm) #for text mining functions
library(corrplot) #for creating plots of correlation matrices
library(randomForest) #for random forest decision tree analysis

#See complete description of tm package, along with an index of all functions
library(help=tm)

rawData <- read.csv("DefaultWHIDView2.csv",header=TRUE)
head(rawData) #view first few rows of data
colnames(rawData) #show the column names

data <- Corpus(VectorSource(rawData[,"IncidentDescription"]))

#Cleanup text
data2 = tm_map(data, stripWhitespace)
#data2 = tm_map(data2, stemDocument)
data2 = tm_map(data2, tolower)
stopWords = c(stopwords("english"))
data2 = tm_map(data2, removeWords, stopWords)
data2 = tm_map(data2, removePunctuation)
data2 = tm_map(data2, removeNumbers)

inspect(data2[1:5])

#Make a word frequency matrix, with documents as rows, and terms as columns
dtm = DocumentTermMatrix(data2)
inspect(dtm[1:5,1:5])

#Remove and sparse terms a given percentage of sparse (i.e., 0) occurence
dtm = removeSparseTerms(dtm, 0.90)
inspect(dtm[1:5,1:5])
inspect(dtm)

summary(inspect(dtm[,1:3]))

#Find terms that occur at least n times
findFreqTerms(dtm, 100)

#Find associated terms with the term, "attack", and a correlation of at least r
findAssocs(dtm, "attack", 0.1)

#Find associated terms with the term, "service", and a correlation of at least r
findAssocs(dtm, "service", 0.1)

#Make a word frequency matrix, with terms as rows, and documents as columns
#Note that the findings are the same, but the layout is visually different
tdm = TermDocumentMatrix(data2)
inspect(tdm[1:5,1:5])

tdm = removeSparseTerms(tdm, 0.90)
inspect(tdm[1:5,1:5])

findAssocs(tdm, "attack", 0.1)

#Convert to date format
dateVector <- as.Date(rawData[,"DateOccured"], "%m/%d/%Y")
mnth <- month(dateVector)
yr <- year(dateVector)
dtmAndDates <- data.frame(dateVector,mnth,yr,inspect(dtm))
head(dtmAndDates)

dtmAndYr <- data.frame(yr,inspect(dtm))
(sumByYear <- aggregate(dtmAndYr[,-1], by=list(dtmAndYr$yr), sum))

#Prepare data for correlation analysis
selTermsByYr <- sumByYear[,-1] #remove the year column
rownames(selTermsByYr) <- sumByYear[,1] #make the years into rownames
selTermsByYr #show the result

#Create a correlation matrix on trended data
(corData <- cor(selTermsByYr))

#Create a correlation plot on trended data
png("Figure1.png")
corrplot(corData, method="ellipse")
dev.off()

#Create a dictionary: a subset of terms
d = inspect(DocumentTermMatrix(data2, list(dictionary = c("attack", "security", "site", "web"))))

#Correlation matrix
cor(d) #correlation matrix of dictionary terms only

#Visually compare the terms, "attack", and "Security" in a barplot
par(mfrow=c(2,1)) #group the plots together, one on top of the other
barplot(d[,"attack"],main="Term Frequency: Attack", xlab="Incident", ylab="Frequency")
barplot(d[,"security"],main="Term Frequency: Security", xlab="Incident", ylab="Frequency")

#Create a scatterplot comparing "attack" and "security"
plot(jitter(d[,"attack"])~jitter(d[,"security"]), main="Scatterplot: 'attack' vs 'frequency'",xlab="term: security", ylab="term: attack")

#Visually compare the terms, "site", and "web" in a barplot
par(mfrow=c(2,1))
barplot(d[,"site"],main="Term Frequency: Site", xlab="Days", ylab="Frequency")
barplot(d[,"web"],main="Term Frequency: Web", xlab="Days", ylab="Frequency")

#Create a scatterplot comparing "site" and "web"
png("Figure2.png")
plot(jitter(d[,"site"])~jitter(d[,"web"]), main="Scatterplot: 'site' vs 'web'",xlab="term: web", ylab="term: site")
abline(lm(d[,"site"]~d[,"web"]))
dev.off()

#Do a standard correlation
(corNonSparse <- cor(inspect(dtm))) #correlation matrix of all non-sparse terms
png("corrplotNonSparse.png")
corrplot(corNonSparse,method="ellipse")
dev.off()

#Do a plot on a pairwise, non-parametric correlation
(corNonSparse <- cor(inspect(dtm),method="spearman",use="pairwise")) #correlation matrix of all non-sparse terms, non-parametric, pairwise
png("corrplotNonSparse.png")
corrplot(corNonSparse,method="ellipse")
dev.off()


#Hierarchical cluster analysis
png("Figure3.png")
hClust <- hclust(dist(dtm))
plot(hClust, labels=FALSE)
dev.off()

#K-means cluster analysis
kmClust <- kmeans(dtm,centers=3)
print(kmClust)

#Assign cluster membership to the orginal data
dtmWithClust <- data.frame(inspect(dtm), kmClust$cluster)
print(dtmWithClust)

rfClust <- randomForest(kmClust.cluster~., data=dtmWithClust, importance=TRUE, proximity=TRUE)
print(rfClust)
importance(rfClust)


