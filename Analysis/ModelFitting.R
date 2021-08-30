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
lm1<- glm(log(cwe_checker) ~ log(size) +domain+compiler+static,data=data[,])
summary(lm1)
par(mfrow=c(2,2))
plot(lm1)
#Removed non-sig variables removing by lowest coefficient
lm1<- glm(log(cwe_checker) ~ log(size) + static,data=data[,])
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
#AIC: NA, still has some issues it seems like

m2 <- zeroinfl(cve_bin_tool ~ log(size) +domain+compiler+static|log(size) +domain+compiler+static,data=data, dist="poisson")
AIC(poisglm2, m2)


#Removing lowest coef of non-significant variables, re-running each time until all sig. variables
m2 <- zeroinfl(cve_bin_tool ~ domain+compiler+static|log(size)+domain,data=data, dist="poisson")
summary(m2)
#Seems to be the best

res <- residuals(m2)
plot(log(predict(m2)), res)
abline(h=0, lty=2)
#Better at least?



##Yara Rules Model Fitting###############################################
poisglm3 <- glm(yara_rules ~ log(size) +domain+compiler+static, family=poisson(link="log"),data=data)

summary(poisglm3)
plot(allEffects(poisglm3,resid=T),type="link",grid=T)
par(mfrow=c(2,2))
plot(poisglm3)

m3all <- zeroinfl(yara_rules ~ log(size) +domain+compiler+static|log(size) +domain+compiler+static, dist="poisson",data=data)
AIC(poisglm3, m3all)#m3all better

#Removing lowest coef of non-significant variables, re-running each time until all sig. variables
m3 <- zeroinfl(yara_rules ~ log(size) +domain+compiler|log(size)+static, dist="poisson",data=data)
AIC(m3,m3all) #m3 better
summary(m3)

res <- residuals(m3)
plot(log(predict(m3)), res)
abline(h=0, lty=2)
#Better? Unsure.

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
expCoefm3 <- matrix(expCoefm3,ncol=2)
rownames(expCoefm3) <- names(coef(m1))
colnames(expCoefm3) <- c("Count_model","Zero_inflation_model")
expCoefm3