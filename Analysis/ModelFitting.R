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
library(grid)
library(gridExtra)
library(foreign)
library(ggplot2)
library(MASS)
library(pscl)
library(car)
library(effects)
library(AER)

data = read.csv("Data/DataWithDomainNoDependency.csv")

#Turn compiler into a binary factor
for (i in 1:nrow(data)) {
  if (data[i,"compiler"]!="Unk") 
    data[i,"compiler"] <- "GCC"
}

data[,"compiler"] <- as.factor(data[,"compiler"])
data[,"static"] <- as.factor(data[,"static"])
data[,"domain"] <- as.factor(data[,"domain"])
data[,"cbtFindings"]<- ifelse(data[,"cve_bin_tool"]==0,0,1)
data[,"yrFindings"]<- ifelse(data[,"yara_rules"]==0,0,1)

data[,"cbtFindings"]<- as.factor(data[,"cbtFindings"])
data[,"yrFindings"]<- as.factor(data[,"yrFindings"])



#CWE_Checker Model fitting:############################################
lm1<- lm(log(cwe_checker) ~ log(size) +domain+compiler+static,data=data)
summary(lm1)
par(mfrow=c(2,2))
plot(lm1)
#Removed non-sig variables removing by lowest coefficient
lm1<- lm(log(cwe_checker) ~ log(size) + static,data=data[,])
summary(lm1)
par(mfrow=c(2,2))
plot(lm1)
#Assumptions may be violated a little bit (Mainly normal distribution of residuals), but model is robust enough to these changes.



#CVE-Bin-Tool Model Fitting################################################
poisglm2 <- glm(cve_bin_tool ~ log(size) +domain+compiler+static, family=poisson(link="log"),data=data)
#Overdispersion for sure, diagnostic plots not looking great either
summary(poisglm2)
par(mfrow=c(2,2))
plot(poisglm2)
plot(allEffects(poisglm2,resid=T),type="link",grid=T)
#Pretty clearly breaks assumptions, right?

#poisglm2 <- glm(cve_bin_tool ~ log(size) +domain+compiler+static, family=quasipoisson,data=data)
#AIC: NA, has some issues it seems like

m2all <- zeroinfl(cve_bin_tool ~ log(size) +domain+compiler+static|log(size) +domain+compiler+static,data=data, dist="poisson")
AIC(poisglm2, m2all)


#Removing lowest coef of non-significant variables, re-running each time until all sig. variables
m2 <- zeroinfl(cve_bin_tool ~ domain+compiler+static|log(size)+domain,data=data, dist="poisson")
summary(m2)
AIC(m2all,m2)

m2nbm <- zeroinfl(cve_bin_tool~log(size) +domain+compiler+static|log(size) +domain,data=data, dist="negbin")
summary(m2nbm)
AIC(m2,m2nbm)
#Seems to be the best

logModel <- glm(cbtFindings ~ log(size) +domain,data=data,family="binomial")
summary(logModel)
plot(logModel)

##Yara Rules Model Fitting###############################################
poisglm3 <- glm(yara_rules ~ log(size) +domain+compiler+static, family=poisson(link="log"),data=data)
summary(poisglm3)
plot(allEffects(poisglm3,resid=T),type="link",grid=T)
par(mfrow=c(2,2))
plot(poisglm3)

dispersiontest(poisglm3)

#Check if offset model is better
poisglm3offset <- glm(yara_rules ~ offset(log(size)) +domain+compiler+static, family=poisson(link="log"),data=data)
AIC(poisglm3,poisglm3offset) #Offset not better

#Fit NBM, check if better
nbm1 <- glm.nb(yara_rules ~ log(size) +domain+compiler+static, data=data)
summary(nbm1)
AIC(poisglm3,nbm1) #Performs better than Poisson



zeroInflatedPois <- zeroinfl(yara_rules ~ log(size) +domain+compiler+static|log(size) +domain+compiler+static, dist="poisson",data=data)
AIC(poisglm3, zeroInflatedPois,nbm1)#zeroinf better. but only barely

m3nbm <- zeroinfl(yara_rules ~ log(size) +domain+compiler+static|log(size) +domain+compiler+static, dist="negbin",data=data)
AIC(m3nbm, m3all)#m3all better, stick with poisson


#Removing lowest coef of non-significant variables, re-running each time until all sig. variables
m3 <- glm.nb(yara_rules ~ log(size) +domain+static, data=data)
summary(m3)

res <- residuals(m3nbm)
plot(log(predict(m3nbm)), res)
abline(h=0, lty=2)
#A little bit better

#Interpretation####################################
## Exponentiated coefficients, cve-bin-tool
expCoefm2 <- exp(coef((m2)))
expCoefm2 <- matrix(expCoefm2,ncol=2,nrow=4)
rownames(expCoefm2) <- c("Intercept","log(Size)", "Domain","Static compilation")
colnames(expCoefm2) <- c("Count_model","Zero_inflation_model")
expCoefm2[8] <-NA
expCoefm2

 ## Exponentiated coefficients, yara-rules
expCoefm3 <- exp(coef((m3)))
expCoefm3
