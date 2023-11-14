import 'dart:convert';

import 'package:flutter/material.dart';
import 'package:flutter_dotenv/flutter_dotenv.dart';
import 'package:orury/core/theme/constant/app_colors.dart';
import 'package:orury/presentation/routes/route_path.dart';

import '../../global/http/http_request.dart';
import '../Board/board.dart';
import '../Board/post.dart';
import '../routes/routes.dart';


class MainScreen extends StatefulWidget {
  MainScreen({Key? key}) : super(key: key);

  @override
  _MainScreenState createState() => _MainScreenState();
}

class _MainScreenState extends State<MainScreen> {

  // 게시글 목록 조회
  Future<List<Post>> fetchPosts() async {
    final response = await sendHttpRequest(
      'GET',
      Uri.http(dotenv.env['API_URL']!, '/api/board/1'),
      // Uri.http(dotenv.env['AWS_API_URL']!, '/api/board/1'),
    );

    final jsonData = jsonDecode(utf8.decode(response.bodyBytes));
    final board = Board.fromJson(jsonData);
    return board.postList;
  }


  @override
  Widget build(BuildContext context) {
    return Scaffold(
      appBar: AppBar(
        centerTitle: true,
        title: Text('Orury!'),
      ),
      body: FutureBuilder<List<Post>>(
        future: fetchPosts(),
        builder: (context, snapshot) {
          if (snapshot.connectionState == ConnectionState.waiting) {
            return Center(child: CircularProgressIndicator());
          } else if (snapshot.hasError) {
            return Center(child: Text('Error: ${snapshot.error}'));
          } else if (!snapshot.hasData || snapshot.data!.isEmpty) {
            return Center(child: Text('No data available.'));
          } else {
            return ListView.builder(
              itemCount: snapshot.data?.length,
              itemBuilder: (context, index) {
                final post = snapshot.data![index];
                return ListTile(
                  // tileColor: AppColors.background,
                  selectedTileColor: AppColors.oruryMain,
                  leading: post.thumbnailUrl != null
                      ? Image.network(
                    dotenv.env['IMGUR_GET_IMAGE_URL']! + post.thumbnailUrl!,
                    width: 80,
                    height: 80,
                    fit: BoxFit.cover,
                    errorBuilder: (BuildContext context, Object exception,
                        StackTrace? stackTrace) {
                      return const SizedBox
                          .shrink(); // 이미지 로드에 실패하면 아무것도 표시하지 않음
                    },
                  )
                      : null,
                  // null인 경우 leading 생략
                  title: Text(post.postTitle),
                  subtitle: Text(post.userNickname),
                  onTap: () {
                    // 게시물을 누르면 상세 페이지로 이동
                    router.push(
                      RoutePath.postDetail,
                      extra: post.id,
                    );
                  },
                  trailing: Row(
                    mainAxisSize: MainAxisSize.min,
                    children: [
                      Icon(Icons.thumb_up, size: 15,), // 좋아요 아이콘
                      Text(post.likeCnt.toString()), // 좋아요 수
                      SizedBox(width: 20), // 간격 조절
                      Icon(Icons.comment, size: 15,), // 댓글 아이콘
                      Text(post.commentList.length.toString()), // 댓글 수
                    ],
                  ),
                );
              },
            );
          }
        },
      ),
      bottomNavigationBar: BottomNavigationBar(
        showUnselectedLabels: false,
        showSelectedLabels: false,
        items: [
          BottomNavigationBarItem(
            icon: Icon(
              Icons.people,
              color: Colors.blue, // 'board' 탭은 파란색 아이콘
            ),
            label: 'board',
          ),
          BottomNavigationBarItem(
            icon: Icon(
              Icons.map,
              color: Colors.black, // 다른 탭들은 검은색 아이콘
            ),
            label: 'map',
          ),
          BottomNavigationBarItem(
            icon: Icon(
              Icons.person,
              color: Colors.black,
            ),
            label: 'profile',
          ),
          BottomNavigationBarItem(
            icon: Icon(
              Icons.settings,
              color: Colors.black,
            ),
            label: 'setting',
          ),
        ],
        backgroundColor: AppColors.oruryMain,
      ),
      floatingActionButton: FloatingActionButton(
        onPressed: () {
          router.push(RoutePath.postCreate);
        },
        child: Icon(Icons.add),
      ),
    );
  }
}
// }
