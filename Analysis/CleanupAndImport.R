library(readr)
library(tidyverse)
library(ggplot2)
library(GGally)
library(ggfortify)
library(FactoMineR)
library(factoextra)
library(ggpubr)
library(rstatix)
library(quantreg)
library(gridExtra)


###First step is to load in all the data and make sure it is cleaned up

binSizes <- read_table2("Data/BinSizes.txt", col_names = c("binary","size"))
metaData <- read_delim("Data/benchmarkMeta.txt", 
                       "\t", escape_double = FALSE, col_names = FALSE, 
                       trim_ws = TRUE)
outputData <- read_csv("Data/BenchmarkToolOutput.txt")
yaraOutput <- read_csv("Data/YaraOutput.txt")
benchmarkMeta <- read_csv("Data/benchmarkMeta.txt", 
                          col_names = FALSE)
metaDataBinaries <- benchmarkMeta[1]


columns <- c("binary", "cwe_checker", "yara_rules", "cve_bin_tool", "norm_cwe_checker", "norm_yara_rules", "size", "compiler", "static")
data <- data.frame(matrix(NA, nrow = nrow(binSizes), ncol = length(columns)))
colnames(data)<- columns





#Get binary names for all binaries with >0 findings from cwe_checker
data[,"binary"] <- outputData[which(rowSums(outputData[,"cwe_checker"]!=0)>0),"tool"]

for (i in 1:nrow(data)) {
  #Name of binary
  bin <- data[i,"binary"]
  sizeIndex <- which(binSizes[,"binary"]==bin)
  
  #get values for tools
  outputIndex <- which(outputData[,"tool"]==bin)
  data[i,"cwe_checker"] <- outputData[outputIndex,"cwe_checker"]
  data[i,"norm_cwe_checker"] <- outputData[outputIndex,"cwe_checker"]/binSizes[sizeIndex,"size"]
  data[i,"cve_bin_tool"] <-outputData[outputIndex,"cve-bin-tool"]
  yaraIndex <- which(yaraOutput[,"binary"]==bin)
  data[i,"yara_rules"] <-yaraOutput[yaraIndex,"out"]
  data[i,"norm_yara_rules"] <-yaraOutput[yaraIndex,"out"]/binSizes[sizeIndex,"size"]
  data[i,"norm_cve_bin_tool"] <-data[i,"cve_bin_tool"]/binSizes[sizeIndex,"size"]
  
  #fill size info
  data[i,"size"] <- binSizes[sizeIndex,"size"]
  #Get other metadata for file
  metaIndex <- which(metaDataBinaries==bin)
  
  data[i,"static"] <- grepl("EXEC",metaData[metaIndex,])
  
  #Check if meta data includes compiler info, if it does set the value otherwise
  #set as NA
  temp <- gsub(".*compiler: (.*\\(.*\\)).*","\\1",c(metaData[metaIndex,]))
  if (metaData[metaIndex,]==temp) 
    data[i,"compiler"] <- "Unk"
  else 
    data[i,"compiler"] <- temp
}

write.csv(data,"Data.csv")