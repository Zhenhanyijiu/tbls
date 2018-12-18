package combine

import (
	"fmt"
	"time"
)

//combination problem ,choice m from n
func TestComibine() {
	nums := []int{0, 1, 2, 3, 4, 5, 6, 7, 8, 9}
	m := 5

	timeStart := time.Now()
	n := len(nums)
	indexs := CombineResult(n, m)
	result := FindNumsByIndexs(nums, indexs)
	timeEnd := time.Now()

	fmt.Println("count:", len(result))
	fmt.Println("result:", result)
	//fmt.Println("indexs:", indexs)
	fmt.Println("time consume:", timeEnd.Sub(timeStart))
	//if the result is right or not
	rightCount := CountCombination(n, m)
	if rightCount == len(result) {
		fmt.Println("result is right")
	} else {
		fmt.Println("result is wrong，the right result is：", rightCount)
	}
}

//组合算法(从nums中取出m个数)
func CombineResult(n int, m int) [][]int {
	if m < 1 || m > n {
		fmt.Println("Illegal argument. Param m must between 1 and len(nums).")
		return [][]int{}
	}

	//保存最终结果的数组，总数直接通过数学公式计算
	result := make([][]int, 0, CountCombination(n, m))
	//保存每一个组合的索引的数组，1表示选中，0表示未选中
	indexs := make([]int, n)
	for i := 0; i < n; i++ {
		if i < m {
			indexs[i] = 1
		} else {
			indexs[i] = 0
		}
	}

	//第一个结果
	result = addTo(result, indexs)
	for {
		find := false
		//每次循环将第一次出现的 1 0 改为 0 1，同时将左侧的1移动到最左侧
		for i := 0; i < n-1; i++ {
			if indexs[i] == 1 && indexs[i+1] == 0 {
				find = true

				indexs[i], indexs[i+1] = 0, 1
				if i > 1 {
					moveOneToLeft(indexs[:i])
				}
				result = addTo(result, indexs)

				break
			}
		}

		//本次循环没有找到 1 0 ，说明已经取到了最后一种情况
		if !find {
			break
		}
	}

	return result
}

//将ele复制后添加到arr中，返回新的数组
func addTo(arr [][]int, ele []int) [][]int {
	newEle := make([]int, len(ele))
	copy(newEle, ele)
	arr = append(arr, newEle)

	return arr
}

func moveOneToLeft(leftNums []int) {
	//计算有几个1
	sum := 0
	for i := 0; i < len(leftNums); i++ {
		if leftNums[i] == 1 {
			sum++
		}
	}

	//将前sum个改为1，之后的改为0
	for i := 0; i < len(leftNums); i++ {
		if i < sum {
			leftNums[i] = 1
		} else {
			leftNums[i] = 0
		}
	}
}

//根据索引号数组得到元素数组
func FindNumsByIndexs(nums []int, indexs [][]int) [][]int {
	if len(indexs) == 0 {
		return [][]int{}
	}

	result := make([][]int, len(indexs))

	for i, v := range indexs {
		line := make([]int, 0)
		for j, v2 := range v {
			if v2 == 1 {
				line = append(line, nums[j])
			}
		}
		result[i] = line
	}

	return result
}

//compute the number of permutation (n,m)
func CountPermutation(n int, m int) int {
	return factorial(n) / factorial(n-m)
}

//compute the number of combination (n,m)
func CountCombination(n int, m int) int {
	return factorial(n) / (factorial(n-m) * factorial(m))
}

//compute the factorial for n
func factorial(n int) int {
	result := 1
	for i := 2; i <= n; i++ {
		result *= i
	}

	return result
}

//从n个数中取出m个进行排列，其实就是组合算法之后，对选中的m个数进行全排列
func PermutationResult(nums int, m int) [][]int {
	//组合结果
	zuhe := CombineResult(nums, m)

	//保存最终排列结果
	result := make([][]int, 0)
	//遍历组合结果，对每一项进行全排列
	for _, v := range zuhe {
		p := CompletePermutation(v)
		result = append(result, p...)
	}

	return result
}

//n个数全排列//如输入[1 2 3]，则返回[123 132 213 231 312 321]
func CompletePermutation(nums []int) [][]int {
	COUNT := len(nums)
	//检查
	if COUNT == 0 || COUNT > 10 {
		panic("Illegal argument. nums size must between 1 and 9.")
	}

	//如果只有一个数，则直接返回
	if COUNT == 1 {
		return [][]int{nums}
	}

	//否则，将最后一个数插入到前面的排列数中的所有位置
	return insertItem(CompletePermutation(nums[:COUNT-1]), nums[COUNT-1])
}
func insertItem(res [][]int, insertNum int) [][]int {
	//保存结果的slice
	result := make([][]int, len(res)*(len(res[0])+1))

	index := 0
	for _, v := range res {
		for i := 0; i < len(v); i++ {
			//在v的每一个元素前面插入新元素
			result[index] = insertToSlice(v, i, insertNum)
			index++
		}

		//在v最后面插入新元素
		result[index] = append(v, insertNum)
		index++
	}

	return result
}

//将元素value插入到数组nums中索引为index的位置
func insertToSlice(nums []int, index int, value int) []int {
	result := make([]int, len(nums)+1)
	copy(result[:index], nums[:index])
	result[index] = value
	copy(result[index+1:], nums[index:])

	return result
}
